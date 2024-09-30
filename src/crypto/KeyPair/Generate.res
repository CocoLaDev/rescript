let rsa = () => {
  let {publicKey, privateKey} = KeyPair.generateRSAPair("rsa", {"modulusLength": 2048})
  (publicKey, privateKey)
}

let ec = () => {
  let {publicKey, privateKey} = KeyPair.generateECPair("ec", {"namedCurve": "secp256k1"})
  (publicKey, privateKey)
}