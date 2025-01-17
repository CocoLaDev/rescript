// Fonction pour hacher des données avec SHA-256
let hashSha256 = (data: string): result<string, Errors.error> => {
  try {
    let hash = Hashing.createHash("sha256")
    Ok(hash->Hashing.update(data)->Hashing.digest("hex"))
  } catch {
  | Js.Exn.Error(obj) => 
      switch Js.Exn.message(obj) {
      | Some(msg) => Error(Errors.Error(msg))
      | None => Error(Errors.Error("Unknown hashing error"))
      }
  }
}
