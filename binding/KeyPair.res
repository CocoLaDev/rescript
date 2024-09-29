// Définir un type pour le retour de generateKeyPairSync
type keyPair = {
  publicKey: string,
  privateKey: string,
}

// External binding à la fonction Node.js
@module("crypto")
external generateKeyPairSync: (
  string, // Type de clé, ex: "rsa"
  {
    "modulusLength": int, // Taille du module RSA en bits
  }
) => keyPair = "generateKeyPairSync"
