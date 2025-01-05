// Generated by ReScript, PLEASE EDIT WITH CARE

import * as $$Crypto from "./Crypto.res.mjs";

console.log("Utilisateur 1 : Génération de la paire de clés EC...");

var pair = $$Crypto.generateEcKeyPair();

var match;

match = pair.TAG === "Ok" ? pair._0 : [
    "",
    ""
  ];

var privateKey1 = match[1];

var publicKey1 = match[0];

console.log("Utilisateur 2 : Génération de la paire de clés EC...");

var pair$1 = $$Crypto.generateEcKeyPair();

var match$1;

match$1 = pair$1.TAG === "Ok" ? pair$1._0 : [
    "",
    ""
  ];

var privateKey2 = match$1[1];

var publicKey2 = match$1[0];

console.log("Utilisateur 3 (malveillant) : Génération de la paire de clés EC...");

var pair$2 = $$Crypto.generateEcKeyPair();

var match$2;

match$2 = pair$2.TAG === "Ok" ? pair$2._0 : [
    "",
    ""
  ];

var privateKey3 = match$2[1];

var message1 = "Hello from User 1!";

var message2 = "Hello from User 2!";

var aesKey = "12345678901234567890123456789012";

var aesIv = "1234567890123456";

function sendMessage(senderPrivateKey, message) {
  console.log("Chiffrement du message...");
  var data = $$Crypto.encryptAes(aesKey, aesIv, message);
  var encryptedMessage;
  encryptedMessage = data.TAG === "Ok" ? data._0 : "Error during encryption";
  console.log("Message : " + message);
  console.log("Message chiffré : " + encryptedMessage);
  console.log("Signature du message chiffré...");
  var sig = $$Crypto.signData(encryptedMessage, senderPrivateKey);
  var signature;
  signature = sig.TAG === "Ok" ? sig._0 : "Error signing message";
  console.log("Signature (buffer) : ");
  console.log(signature);
  return [
          encryptedMessage,
          signature
        ];
}

function receiveMessage(senderPublicKey, encryptedMessage, signature) {
  console.log("Vérification de la signature par le destinataire...");
  var isValid = $$Crypto.verifySignature(encryptedMessage, signature, senderPublicKey);
  var isSignatureValid;
  isSignatureValid = isValid.TAG === "Ok" ? isValid._0 : false;
  if (isSignatureValid) {
    console.log("Signature valide.");
    console.log("Déchiffrement du message...");
    var decryptedMessage = $$Crypto.decryptAes(aesKey, aesIv, encryptedMessage);
    if (decryptedMessage.TAG === "Ok") {
      console.log("Message déchiffré : " + decryptedMessage._0);
      return ;
    }
    console.log("Erreur de déchiffrement : " + decryptedMessage._0._0);
    return ;
  }
  console.log("Signature invalide.");
}

console.log("\n--- Utilisateur 1 envoie un message à Utilisateur 2 ---");

var match$3 = sendMessage(privateKey1, message1);

console.log("--- Utilisateur 2 reçoit le message ---");

receiveMessage(publicKey1, match$3[0], match$3[1]);

console.log("\n--- Utilisateur 2 envoie un message à Utilisateur 1 ---");

var match$4 = sendMessage(privateKey2, message2);

var signature = match$4[1];

var encryptedMessage = match$4[0];

console.log("--- Utilisateur 1 reçoit le message ---");

receiveMessage(publicKey2, encryptedMessage, signature);

console.log("\n--- Utilisateur 3 tente d'usurper l'identité de l'Utilisateur 2 ---");

var messageAttaque = "Message malveillant se faisant passer pour Utilisateur 2!";

var match$5 = sendMessage(privateKey3, messageAttaque);

var signatureAttaque = match$5[1];

var encryptedMessageAttaque = match$5[0];

console.log("--- Utilisateur 1 reçoit le message ---");

receiveMessage(publicKey2, encryptedMessageAttaque, signatureAttaque);

var publicKey3 = match$2[0];

export {
  publicKey1 ,
  privateKey1 ,
  publicKey2 ,
  privateKey2 ,
  publicKey3 ,
  privateKey3 ,
  message1 ,
  message2 ,
  aesKey ,
  aesIv ,
  sendMessage ,
  receiveMessage ,
  encryptedMessage ,
  signature ,
  messageAttaque ,
  encryptedMessageAttaque ,
  signatureAttaque ,
}
/*  Not a pure module */
