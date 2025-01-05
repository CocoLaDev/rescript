// Fonction pour encrypter une donnée avec AES-256-CBC
let encryptAes = (~key: string, ~iv: string, data: string): result<string, Errors.error> => {
  try {
    let cipher = Encryption.createCipheriv("aes-256-cbc", key, iv)
    let encrypted = cipher->Encryption.update(data, "utf8", "hex")
    let final = cipher->Encryption.final("hex")
    Ok(encrypted ++ final)
  } catch {
  | Js.Exn.Error(obj) =>
      switch Js.Exn.message(obj) {
      | Some(msg) => Error(Errors.Error(msg))
      | None => Error(Errors.Error("Unknown encryption error"))
      }
  }
}

// Fonction pour décrypter une donnée avec AES-256-CBC
let decryptAes = (~key: string, ~iv: string, encryptedData: string): result<string, Errors.error> => {
  try {
    let decipher = Decryption.createDecipheriv("aes-256-cbc", key, iv)
    let decrypted = decipher->Decryption.update(encryptedData, "hex", "utf8")
    let final = decipher->Decryption.final("utf8")
    Ok(decrypted ++ final)
  } catch {
  | Js.Exn.Error(obj) =>
      switch Js.Exn.message(obj) {
      | Some(msg) => Error(Errors.Error(msg))
      | None => Error(Errors.Error("Unknown decryption error"))
      }
  }
}