// Définir un type pour le retour de sha256
type hashObj

// External binding à la fonction Node.js
@module("crypto")
external createHash: string => hashObj = "createHash"

@send external update: (hashObj, string) => hashObj = "update"

@send external digest: (hashObj, string) => string = "digest"
