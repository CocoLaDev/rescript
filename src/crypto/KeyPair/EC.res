// Fonction pour générer une paire de clés ECDSA
let generateEcKeyPair = (): result<(string, string), Errors.error> => {
  try {
    let {publicKey, privateKey} = KeyPair.generateECPair("ec", {"namedCurve": "secp256k1"})
    Ok((publicKey, privateKey))
  } catch {
  | Js.Exn.Error(obj) =>
      switch Js.Exn.message(obj) {
      | Some(msg) => Error(Error(msg))
      | None => Error(Error("Unknown EC key pair generation error"))
      }
  }
}