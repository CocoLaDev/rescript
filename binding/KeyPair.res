// Définir un type pour le retour de generateKeyPairSync
type keyPair = {
  publicKey: Pairs.publicKey,
  privateKey: Pairs.privateKey,
}

// External binding à la fonction Node.js
@module("crypto")
external generateRSAPair: (
  string, // Type de clé ("rsa")
  {
    "modulusLength": int, // Taille du module RSA
  }
) => keyPair = "generateKeyPairSync"

// External binding pour générer des clés ECC
@module("crypto")
external generateECPair: (
  string, // Type de clé ("ec")
  {
    "namedCurve": string, // Nom de la courbe elliptique
  }
) => keyPair = "generateKeyPairSync"