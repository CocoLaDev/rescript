let generate = () => {
  let {publicKey, privateKey} = KeyPair.generateKeyPairSync("rsa", {"modulusLength": 2048})
  (publicKey, privateKey)
}
