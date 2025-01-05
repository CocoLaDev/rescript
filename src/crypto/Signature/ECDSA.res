// Fonction pour signer des données
let signData = (data: string, privateKey: Pairs.privateKey): result<string, Errors.error> => {
  try {
    Ok(Signature.sign("SHA256", data, {"key": privateKey, "dsaEncoding": "der"}))
  } catch {
  | Js.Exn.Error(obj) => 
      switch Js.Exn.message(obj) {
      | Some(msg) => Error(Errors.Error(msg))
      | None => Error(Errors.Error("Unknown signature error"))
      }
  }
}

// Fonction pour vérifier la signature
let verifySignature = (data: string, signature: string, publicKey: Pairs.publicKey): result<bool, Errors.error> => {
  try {
    Ok(Signature.verify("SHA256", data, {"key": publicKey, "dsaEncoding": "der"}, signature))
  } catch {
  | Js.Exn.Error(obj) => 
      switch Js.Exn.message(obj) {
      | Some(msg) => Error(Errors.Error(msg))
      | None => Error(Errors.Error("Unknown signature error"))
      }
  }
}
