// Définir un type pour le Decipher
type decipherObj

// External binding pour créer un déchiffreur AES
@module("crypto")
external createDecipheriv: (string, string, string) => decipherObj = "createDecipheriv"

// External binding pour mettre à jour le déchiffrement
@send external update: (decipherObj, string, string, string) => string = "update"

// External binding pour terminer le déchiffrement
@send external final: (decipherObj, string) => string = "final"