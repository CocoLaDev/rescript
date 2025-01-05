let passed = ref(0)
let failed = ref(0)

let assertTrue = (name, condition) => {
  if condition {
    Console.log(`✅ ${name}`)
    passed.contents = passed.contents + 1
  } else {
    Console.log(`❌ ${name}`)
    failed.contents = failed.contents + 1
  }
}

Console.log("MessageEncryption.res")

// Test de chiffrement/déchiffrement
let testEncryptionDecryption = () => {
  let message = "Hello, World!"
  let key = "12345678901234567890123456789012"
  let iv = "1234567890123456"

  switch Crypto.encryptAes(~key, ~iv, message) {
  | Ok(encrypted) => {
      assertTrue("Encryption: result not empty", encrypted != "")
      switch Crypto.decryptAes(~key, ~iv, encrypted) {
      | Ok(decrypted) => assertTrue("Decryption: matches original", decrypted == message)
      | Error(_) => assertTrue("Decryption should not fail", false)
      }
    }
  | Error(_) => assertTrue("Encryption should not fail", false)
  }
}

// Run tests
testEncryptionDecryption()

// Print summary
Console.log(`Tests completed: ${Belt.Int.toString(passed.contents + failed.contents)} total, ${Belt.Int.toString(passed.contents)} passed, ${Belt.Int.toString(failed.contents)} failed\n`) 