// Fonction pour signer des données
let signData = (data: string, privateKey: Pairs.privateKey): string => {
  Signature.sign("SHA256", data, {"key": privateKey, "dsaEncoding": "der"})
}

// Fonction pour vérifier la signature
let verifySignature = (data: string, signature: string, publicKey: Pairs.publicKey): bool => {
  Signature.verify("SHA256", data, {"key": publicKey, "dsaEncoding": "der"}, signature)
}
