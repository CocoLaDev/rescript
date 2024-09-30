// Rabbit stream cipher algorithm in ReScript

type streamCipher

let S = Array.make(4, 0)
let C_ = Array.make(8, 0)
let G = Array.make(8, 0)

let nextState = (self) => {
  // Shortcuts
  let X = self._X
  let C = self._C

  // Save old counter values
  for (i in 0 to 7) {
    Array.set(C_, i, Array.getUnsafe(C, i))
  }

  // Calculate new counter values
  Array.set(C, 0, (Array.getUnsafe(C, 0) + 0x4d34d34d + self._b) land 0xffffffff)
  Array.set(C, 1, (Array.getUnsafe(C, 1) + 0xd34d34d3 + (if Array.getUnsafe(C, 0) < Array.getUnsafe(C_, 0) then 1 else 0)) land 0xffffffff)
  Array.set(C, 2, (Array.getUnsafe(C, 2) + 0x34d34d34 + (if Array.getUnsafe(C, 1) < Array.getUnsafe(C_, 1) then 1 else 0)) land 0xffffffff)
  Array.set(C, 3, (Array.getUnsafe(C, 3) + 0x4d34d34d + (if Array.getUnsafe(C, 2) < Array.getUnsafe(C_, 2) then 1 else 0)) land 0xffffffff)
  Array.set(C, 4, (Array.getUnsafe(C, 4) + 0xd34d34d3 + (if Array.getUnsafe(C, 3) < Array.getUnsafe(C_, 3) then 1 else 0)) land 0xffffffff)
  Array.set(C, 5, (Array.getUnsafe(C, 5) + 0x34d34d34 + (if Array.getUnsafe(C, 4) < Array.getUnsafe(C_, 4) then 1 else 0)) land 0xffffffff)
  Array.set(C, 6, (Array.getUnsafe(C, 6) + 0x4d34d34d + (if Array.getUnsafe(C, 5) < Array.getUnsafe(C_, 5) then 1 else 0)) land 0xffffffff)
  Array.set(C, 7, (Array.getUnsafe(C, 7) + 0xd34d34d3 + (if Array.getUnsafe(C, 6) < Array.getUnsafe(C_, 6) then 1 else 0)) land 0xffffffff)
  self._b = if Array.getUnsafe(C, 7) < Array.getUnsafe(C_, 7) then 1 else 0

  // Calculate the g-values
  for (i in 0 to 7) {
    let gx = Array.getUnsafe(X, i) + Array.getUnsafe(C, i)
    let ga = gx land 0xffff
    let gb = gx lsr 16

    // Calculate high and low result of squaring
    let gh = ((((ga * ga) lsr 17) + ga * gb) lsr 15) + gb * gb
    let gl = (((gx land 0xffff0000) * gx) lor 0) + (((gx land 0x0000ffff) * gx) lor 0)

    // High XOR low
    Array.set(G, i, gh lxor gl)
  }

  // Calculate new state values
  Array.set(X, 0, (Array.getUnsafe(G, 0) + ((Array.getUnsafe(G, 7) lsl 16) lor (Array.getUnsafe(G, 7) lsr 16)) + ((Array.getUnsafe(G, 6) lsl 16) lor (Array.getUnsafe(G, 6) lsr 16))) lor 0)
  Array.set(X, 1, (Array.getUnsafe(G, 1) + ((Array.getUnsafe(G, 0) lsl 8) lor (Array.getUnsafe(G, 0) lsr 24)) + Array.getUnsafe(G, 7)) lor 0)
  Array.set(X, 2, (Array.getUnsafe(G, 2) + ((Array.getUnsafe(G, 1) lsl 16) lor (Array.getUnsafe(G, 1) lsr 16)) + ((Array.getUnsafe(G, 0) lsl 16) lor (Array.getUnsafe(G, 0) lsr 16))) lor 0)
  Array.set(X, 3, (Array.getUnsafe(G, 3) + ((Array.getUnsafe(G, 2) lsl 8) lor (Array.getUnsafe(G, 2) lsr 24)) + Array.getUnsafe(G, 1)) lor 0)
  Array.set(X, 4, (Array.getUnsafe(G, 4) + ((Array.getUnsafe(G, 3) lsl 16) lor (Array.getUnsafe(G, 3) lsr 16)) + ((Array.getUnsafe(G, 2) lsl 16) lor (Array.getUnsafe(G, 2) lsr 16))) lor 0)
  Array.set(X, 5, (Array.getUnsafe(G, 5) + ((Array.getUnsafe(G, 4) lsl 8) lor (Array.getUnsafe(G, 4) lsr 24)) + Array.getUnsafe(G, 3)) lor 0)
  Array.set(X, 6, (Array.getUnsafe(G, 6) + ((Array.getUnsafe(G, 5) lsl 16) lor (Array.getUnsafe(G, 5) lsr 16)) + ((Array.getUnsafe(G, 4) lsl 16) lor (Array.getUnsafe(G, 4) lsr 16))) lor 0)
  Array.set(X, 7, (Array.getUnsafe(G, 7) + ((Array.getUnsafe(G, 6) lsl 8) lor (Array.getUnsafe(G, 6) lsr 24)) + Array.getUnsafe(G, 5)) lor 0)
}

module Rabbit = {
  type t = {
    _X: array<int>,
    _C: array<int>,
    _b: int,
    cfg: {iv: option<array<int>>},
    _key: {words: array<int>},
  }

  let doReset = (self: t): t => {
    let K = self._key.words

    // Swap endian
    let swapEndian = (k: int): int => {
      (((k lsl 8) lor (k lsr 24)) land 0x00ff00ff) lor (((k lsl 24) lor (k lsr 8)) land 0xff00ff00)
    }
    for (i in 0 to 3) {
      Array.set(K, i, swapEndian(Array.getUnsafe(K, i)))
    }

    // Generate initial state values
    let X = [
      Array.getUnsafe(K, 0), (Array.getUnsafe(K, 3) lsl 16) lor (Array.getUnsafe(K, 2) lsr 16),
      Array.getUnsafe(K, 1), (Array.getUnsafe(K, 0) lsl 16) lor (Array.getUnsafe(K, 3) lsr 16),
      Array.getUnsafe(K, 2), (Array.getUnsafe(K, 1) lsl 16) lor (Array.getUnsafe(K, 0) lsr 16),
      Array.getUnsafe(K, 3), (Array.getUnsafe(K, 2) lsl 16) lor (Array.getUnsafe(K, 1) lsr 16)
    ]

    // Generate initial counter values
    let C = [
      (Array.getUnsafe(K, 2) lsl 16) lor (Array.getUnsafe(K, 2) lsr 16), (Array.getUnsafe(K, 0) land 0xffff0000) lor (Array.getUnsafe(K, 1) land 0x0000ffff),
      (Array.getUnsafe(K, 3) lsl 16) lor (Array.getUnsafe(K, 3) lsr 16), (Array.getUnsafe(K, 1) land 0xffff0000) lor (Array.getUnsafe(K, 2) land 0x0000ffff),
      (Array.getUnsafe(K, 0) lsl 16) lor (Array.getUnsafe(K, 0) lsr 16), (Array.getUnsafe(K, 2) land 0xffff0000) lor (Array.getUnsafe(K, 3) land 0x0000ffff),
      (Array.getUnsafe(K, 1) lsl 16) lor (Array.getUnsafe(K, 1) lsr 16), (Array.getUnsafe(K, 3) land 0xffff0000) lor (Array.getUnsafe(K, 0) land 0x0000ffff)
    ]

    // Carry bit
    let _b = 0

    // Iterate the system four times
    let rec iterateSystem n self => {
      if n < 4 {
        nextState(self)
        iterateSystem(n + 1, self)
      } else {
        self
      }
    }
    
    let self = iterateSystem(0, {...self, _X: X, _C: C, _b})

    // Modify the counters
    let modifyCounters = (C: array<int>, X: array<int>) => {
      for (i in 0 to 7) {
        Array.set(C, i, Array.getUnsafe(C, i) lxor Array.getUnsafe(X, (i + 4) land 7))
      }
    }
    modifyCounters(self._C, self._X)

    // IV setup
    switch self.cfg.iv {
    | None => self
    | Some(iv) =>
      let IV_0 = swapEndian(Array.getUnsafe(iv, 0))
      let IV_1 = swapEndian(Array.getUnsafe(iv, 1))

      let i0 = IV_0
      let i2 = IV_1
      let i1 = (i0 lsr 16) lor (i2 land 0xffff0000)
      let i3 = (i2 lsl 16) lor (i0 land 0x0000ffff)

      Array.set(self._C, 0, Array.getUnsafe(self._C, 0) lxor i0)
      Array.set(self._C, 1, Array.getUnsafe(self._C, 1) lxor i1)
      Array.set(self._C, 2, Array.getUnsafe(self._C, 2) lxor i2)
      Array.set(self._C, 3, Array.getUnsafe(self._C, 3) lxor i3)
      Array.set(self._C, 4, Array.getUnsafe(self._C, 4) lxor i0)
      Array.set(self._C, 5, Array.getUnsafe(self._C, 5) lxor i1)
      Array.set(self._C, 6, Array.getUnsafe(self._C, 6) lxor i2)
      Array.set(self._C, 7, Array.getUnsafe(self._C, 7) lxor i3)

      let self = iterateSystem(0, self)
      self
    }
  }

  let doProcessBlock = (self: t, M: array<int>, offset: int): t => {
    let X = self._X

    // Iterate the system
    nextState(self)

    // Generate four keystream words
    Array.set(S, 0, Array.getUnsafe(X, 0) lxor (Array.getUnsafe(X, 5) lsr 16) lxor (Array.getUnsafe(X, 3) lsl 16))
    Array.set(S, 1, Array.getUnsafe(X, 2) lxor (Array.getUnsafe(X, 7) lsr 16) lxor (Array.getUnsafe(X, 5) lsl 16))
    Array.set(S, 2, Array.getUnsafe(X, 4) lxor (Array.getUnsafe(X, 1) lsr 16) lxor (Array.getUnsafe(X, 7) lsl 16))
    Array.set(S, 3, Array.getUnsafe(X, 6) lxor (Array.getUnsafe(X, 3) lsr 16) lxor (Array.getUnsafe(X, 1) lsl 16))

    for (i in 0 to 3) {
      let s = Array.getUnsafe(S, i)
      let s = (((s lsl 8) lor (s lsr 24)) land 0x00ff00ff) lor (((s lsl 24) lor (s lsr 8)) land 0xff00ff00)

      // Encrypt
      Array.set(M, offset + i, Array.getUnsafe(M, offset + i) lxor s)
    }

    self
  }
}
