/* Ce test utilise les algorithmes de chiffrement AES, et de signature ECDSA avec pair de clés EC
 * il permet de créer une paire de clés EC, de chiffrer un message, de le signer et de le vérifier
*/

// Utilisateur 1 : Génération de la clé EC
Console.log("Utilisateur 1 : Génération de la paire de clés EC...")
let (publicKey1, privateKey1) = switch Crypto.generateEcKeyPair() {
  | Ok(pair) => pair
  | Error(_) => ("", "") // Gérer l'erreur selon le besoin
}

// Utilisateur 2 : Génération de la clé EC
Console.log("Utilisateur 2 : Génération de la paire de clés EC...")
let (publicKey2, privateKey2) = switch Crypto.generateEcKeyPair() {
  | Ok(pair) => pair
  | Error(_) => ("", "") // Gérer l'erreur selon le besoin
}

// Utilisateur 3 (malveillant) : Génération de la clé EC
Console.log("Utilisateur 3 (malveillant) : Génération de la paire de clés EC...")
let (publicKey3, privateKey3) = switch Crypto.generateEcKeyPair() {
  | Ok(pair) => pair
  | Error(_) => ("", "") // Gérer l'erreur selon le besoin
}

// Messages des utilisateurs
let message1 = "Hello from User 1!"
let message2 = "Hello from User 2!"

// Clé AES et IV pour le chiffrement
let aesKey = "12345678901234567890123456789012" // 32 caractères = 256 bits
let aesIv = "1234567890123456" // 16 caractères = 128 bits

// Fonction pour chiffrer, signer et envoyer un message
let sendMessage = (senderPrivateKey, message) => {
  Console.log("Chiffrement du message...")
  let encryptedMessage = switch Crypto.encryptAes(~key=aesKey, ~iv=aesIv, message) {
    | Ok(data) => data
    | Error(_) => "Error during encryption"
  }
  Console.log("Message : " ++ message)
  Console.log("Message chiffré : " ++ encryptedMessage)

  Console.log("Signature du message chiffré...")
  let signature = switch Crypto.signData(encryptedMessage, senderPrivateKey) {
    | Ok(sig) => sig
    | Error(_) => "Error signing message"
  }
  Console.log("Signature (buffer) : ")
  Console.log(signature)

  (encryptedMessage, signature)
}

let receiveMessage = (senderPublicKey, encryptedMessage, signature) => {
  Console.log("Vérification de la signature par le destinataire...")
  let isSignatureValid = switch Crypto.verifySignature(encryptedMessage, signature, senderPublicKey) {
    | Ok(isValid) => isValid
    | Error(_) => false
  }
  switch isSignatureValid {
  | true => {
      Console.log("Signature valide.")
      Console.log("Déchiffrement du message...")
      switch Crypto.decryptAes(~key=aesKey, ~iv=aesIv, encryptedMessage) {
      | Ok(decryptedMessage) => Console.log("Message déchiffré : " ++ decryptedMessage)
      | Error(Errors.Error(msg)) => Console.log("Erreur de déchiffrement : " ++ msg)
      }
    }
  | false => Console.log("Signature invalide.")
  }
}

// Échange de messages entre les deux utilisateurs
Console.log("\n--- Utilisateur 1 envoie un message à Utilisateur 2 ---")
let (encryptedMessage, signature) = sendMessage(privateKey1, message1)
Console.log("--- Utilisateur 2 reçoit le message ---")
receiveMessage(publicKey1, encryptedMessage, signature)

Console.log("\n--- Utilisateur 2 envoie un message à Utilisateur 1 ---")
let (encryptedMessage, signature) = sendMessage(privateKey2, message2)
Console.log("--- Utilisateur 1 reçoit le message ---")
receiveMessage(publicKey2, encryptedMessage, signature)

// Tentative d'usurpation d'identité par l'Utilisateur 3
Console.log("\n--- Utilisateur 3 tente d'usurper l'identité de l'Utilisateur 2 ---")
let messageAttaque = "Message malveillant se faisant passer pour Utilisateur 2!"
let (encryptedMessageAttaque, signatureAttaque) = sendMessage(privateKey3, messageAttaque)
Console.log("--- Utilisateur 1 reçoit le message ---")
// Notez que nous utilisons publicKey2 pour la vérification, pas publicKey3
receiveMessage(publicKey2, encryptedMessageAttaque, signatureAttaque)
