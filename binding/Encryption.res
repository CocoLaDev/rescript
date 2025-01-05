type cipherObj

// External binding pour créer un chiffreur AES
@module("crypto")
external createCipheriv: (string, string, string) => cipherObj = "createCipheriv"

// External binding pour mettre à jour le chiffrement
@send external update: (cipherObj, string, string, string) => string = "update"

// External binding pour terminer le chiffrement
@send external final: (cipherObj, string) => string = "final"