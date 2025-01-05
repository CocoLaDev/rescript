
// Test de hashage
Console.log(Crypto.hashSHA256("Hello, World!"))
Console.log(Crypto.hashSHA3("Hello, World!"))

// Test de génération de clés
Console.log(Crypto.generateEcKeyPair())
// Test de vérification de signature
switch Crypto.generateEcKeyPair() {
| Ok((publicKey, privateKey)) => {
    switch Crypto.signData("Hello, World!", privateKey) {
    | Ok(signature) => {
        let isValid = Crypto.verifySignature("Hello, World!", signature, publicKey)
        Console.log(isValid)
      }
    | Error(Error(msg)) => Console.log(`Error generating keys: ${msg}`)
    }
  }
| Error(Error(msg)) => Console.log(`Error generating keys: ${msg}`)
}


let key = "12345678901234567890123456789012" // 32 caractères = 256 bits
let iv = "1234567890123456" // 16 caractères = 128 bits
// Chiffrer la donnée
let encrypted = switch Crypto.encryptAes(~key, ~iv, "Hello, ReScript!") {
  | Ok(data) => Console.log("Encrypted data: " ++ encrypted) 
  data
  | Error(_) => "Error during encryption"
}

// Déchiffrer la donnée
switch Crypto.decryptAes(~key, ~iv, encrypted) {
| Ok(decrypted) => Js.log("Decrypted data: " ++ decrypted)
| Error(Errors.Error(msg)) => Js.log("Decryption error: " ++ msg)
}
