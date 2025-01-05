// Fonction pour générer une paire de clés RSA
let generateRsaKeyPair = (): result<(string, string), Errors.error> => {
  try {
    let {publicKey, privateKey} = KeyPair.generateRSAPair("rsa", {"modulusLength": 2048})
    Ok((publicKey, privateKey))
  } catch {
  | Js.Exn.Error(obj) =>
      switch Js.Exn.message(obj) {
      | Some(msg) => Error(Error(msg))
      | None => Error(Error("Unknown RSA key pair generation error"))
      }
  }
}