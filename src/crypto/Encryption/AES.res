// AES Encryption in ReScript

// S-Box and Sub-Mix Tables
let sBox = Array.make(256, 0)
let invSBox = Array.make(256, 0)
let subMix0 = Array.make(256, 0)
let subMix1 = Array.make(256, 0)
let subMix2 = Array.make(256, 0)
let subMix3 = Array.make(256, 0)
let invSubMix0 = Array.make(256, 0)
let invSubMix1 = Array.make(256, 0)
let invSubMix2 = Array.make(256, 0)
let invSubMix3 = Array.make(256, 0)

// Rcon lookup table
let rcon = [|0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36|]

// Function to compute the lookup tables
let computeTables = () => {
  let d = Array.make(256, 0)
  for (i in 0 to 255) {
    d[i] = if i < 128 { i << 1 } else { (i << 1) ^ 0x11b }
  }

  let rec computeLoop = (x, xi, i) => {
    if i >= 256 {
      ()
    } else {
      let sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4)
      let sx = (sx >>> 8) ^ (sx & 0xff) ^ 0x63
      Array.set(sBox, x, sx)
      Array.set(invSBox, sx, x)

      let x2 = Array.getUnsafe(d, x)
      let x4 = Array.getUnsafe(d, x2)
      let x8 = Array.getUnsafe(d, x4)

      let t = (Array.getUnsafe(d, sx) * 0x101) ^ (sx * 0x1010100)
      Array.set(subMix0, x, (t << 24) | (t >>> 8))
      Array.set(subMix1, x, (t << 16) | (t >>> 16))
      Array.set(subMix2, x, (t << 8) | (t >>> 24))
      Array.set(subMix3, x, t)

      let t = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100)
      Array.set(invSubMix0, sx, (t << 24) | (t >>> 8))
      Array.set(invSubMix1, sx, (t << 16) | (t >>> 16))
      Array.set(invSubMix2, sx, (t << 8) | (t >>> 24))
      Array.set(invSubMix3, sx, t)

      let (x, xi) =
        if x == 0 {
          (1, 1)
        } else {
          (x2 ^ Array.getUnsafe(d, Array.getUnsafe(d, Array.getUnsafe(d, x8 ^ x2))),
           xi ^ Array.getUnsafe(d, Array.getUnsafe(d, xi)))
        }

      computeLoop(x, xi, i + 1)
    }
  }

  computeLoop(0, 0, 0)
}

// AES Encryption Block Function
let aesEncryptBlock = (M, offset, keySchedule) => {
  let s0 = Array.getUnsafe(M, offset) ^ Array.getUnsafe(keySchedule, 0)
  let s1 = Array.getUnsafe(M, offset + 1) ^ Array.getUnsafe(keySchedule, 1)
  let s2 = Array.getUnsafe(M, offset + 2) ^ Array.getUnsafe(keySchedule, 2)
  let s3 = Array.getUnsafe(M, offset + 3) ^ Array.getUnsafe(keySchedule, 3)

  let rec rounds = (round, ksRow, s0, s1, s2, s3) => {
    if round >= 10 {  // Adjust for AES 128/192/256
      (s0, s1, s2, s3)
    } else {
      let t0 =
        (Array.getUnsafe(subMix0, s0 >>> 24) ^
        Array.getUnsafe(subMix1, (s1 >>> 16) & 0xff) ^
        Array.getUnsafe(subMix2, (s2 >>> 8) & 0xff) ^
        Array.getUnsafe(subMix3, s3 & 0xff)) ^ Array.getUnsafe(keySchedule, ksRow)

      let t1 =
        (Array.getUnsafe(subMix0, s1 >>> 24) ^
        Array.getUnsafe(subMix1, (s2 >>> 16) & 0xff) ^
        Array.getUnsafe(subMix2, (s3 >>> 8) & 0xff) ^
        Array.getUnsafe(subMix3, s0 & 0xff)) ^ Array.getUnsafe(keySchedule, ksRow + 1)

      let t2 =
        (Array.getUnsafe(subMix0, s2 >>> 24) ^
        Array.getUnsafe(subMix1, (s3 >>> 16) & 0xff) ^
        Array.getUnsafe(subMix2, (s0 >>> 8) & 0xff) ^
        Array.getUnsafe(subMix3, s1 & 0xff)) ^ Array.getUnsafe(keySchedule, ksRow + 2)

      let t3 =
        (Array.getUnsafe(subMix0, s3 >>> 24) ^
        Array.getUnsafe(subMix1, (s0 >>> 16) & 0xff) ^
        Array.getUnsafe(subMix2, (s1 >>> 8) & 0xff) ^
        Array.getUnsafe(subMix3, s2 & 0xff)) ^ Array.getUnsafe(keySchedule, ksRow + 3)

      rounds(round + 1, ksRow + 4, t0, t1, t2, t3)
    }
  }

  let (finalS0, finalS1, finalS2, finalS3) = rounds(0, 4, s0, s1, s2, s3)

  Array.set(M, offset, finalS0)
  Array.set(M, offset + 1, finalS1)
  Array.set(M, offset + 2, finalS2)
  Array.set(M, offset + 3, finalS3)
}

// Function to initialize the AES encryption process
let initializeAes = (key) => {
  let keyWords = key
  let keySize = Array.length(keyWords)
  let nRounds = keySize + 6
  let ksRows = (nRounds + 1) * 4

  let keySchedule = Array.make(ksRows, 0)
  let rec computeKeySchedule = (ksRow) => {
    if ksRow < ksRows {
      let t = if ksRow < keySize {
        Array.getUnsafe(keyWords, ksRow)
      } else {
        let t = Array.getUnsafe(keySchedule, ksRow - 1)
        if ksRow % keySize == 0 {
          t = (t << 8) | (t >>> 24)
          t = (Array.getUnsafe(sBox, t >>> 24) << 24) | (Array.getUnsafe(sBox, (t >>> 16) & 0xff) << 16) |
              (Array.getUnsafe(sBox, (t >>> 8) & 0xff) << 8) | Array.getUnsafe(sBox, t & 0xff)
          t = t ^ (Array.getUnsafe(rcon, ksRow / keySize) << 24)
        } else if keySize > 6 && ksRow % keySize == 4 {
          t = (Array.getUnsafe(sBox, t >>> 24) << 24) | (Array.getUnsafe(sBox, (t >>> 16) & 0xff) << 16) |
              (Array.getUnsafe(sBox, (t >>> 8) & 0xff) << 8) | Array.getUnsafe(sBox, t & 0xff)
        }
        Array.getUnsafe(keySchedule, ksRow - keySize) ^ t
      }
      Array.set(keySchedule, ksRow, t)
      computeKeySchedule(ksRow + 1)
    } else {
      keySchedule
    }
  }

  let keySchedule = computeKeySchedule(0)

  // Compute inverse key schedule
  let invKeySchedule = Array.make(ksRows, 0)
  let rec computeInvKeySchedule = (invKsRow) => {
    if invKsRow < ksRows {
      let ksRow = ksRows - invKsRow - 1
      let t = if invKsRow % 4 == 0 {
        Array.getUnsafe(keySchedule, ksRow)
      } else {
        Array.getUnsafe(keySchedule, ksRow)
      }

      Array.set(
        invKeySchedule,
        invKsRow,
        if invKsRow < 4 || ksRow < 4 {
          t
        } else {
          Array.getUnsafe(invSubMix0, Array.getUnsafe(sBox, t >>> 24)) ^
          Array.getUnsafe(invSubMix1, Array.getUnsafe(sBox, (t >>> 16) & 0xff)) ^
          Array.getUnsafe(invSubMix2, Array.getUnsafe(sBox, (t >>> 8) & 0xff)) ^
          Array.getUnsafe(invSubMix3, Array.getUnsafe(sBox, t & 0xff))
        }
      )
      computeInvKeySchedule(invKsRow + 1)
    } else {
      invKeySchedule
    }
  }

  let invKeySchedule = computeInvKeySchedule(0)

  (keySchedule, invKeySchedule)
}
