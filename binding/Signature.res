// External binding pour la signature avec ECDSA
@module("crypto")
external sign: (
  string, // algorithm
  string, // Data à signer
  {
    "key": Pairs.privateKey,
    "dsaEncoding": string, // ex: "der"
  }
) => string = "sign"

// External binding pour la vérification de la signature avec ECDSA
@module("crypto")
external verify: (
  string, // algorithm
  string, // Data d'origine
  {
    "key": Pairs.publicKey,
    "dsaEncoding": string, // ex: "der"
  },
  string // Signature
) => bool = "verify"