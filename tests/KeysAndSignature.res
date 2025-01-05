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

Console.log("KeysAndSignature.res")

// Test de génération de clés
let testKeyGeneration = () => {
  switch Crypto.generateEcKeyPair() {
  | Ok((pubKey, privKey)) => {
      assertTrue("Key generation: public key not empty", pubKey != "")
      assertTrue("Key generation: private key not empty", privKey != "")
    }
  | Error(_) => assertTrue("Key generation should not fail", false)
  }
}

// Test de signature/vérification
let testSignatureVerification = () => {
  let message = "Hello, World!"
  switch Crypto.generateEcKeyPair() {
  | Ok((pubKey, privKey)) => {
      switch Crypto.signData(message, privKey) {
      | Ok(signature) => {
          assertTrue("Signature: not empty", signature != "")
          switch Crypto.verifySignature(message, signature, pubKey) {
          | Ok(isValid) => assertTrue("Signature verification", isValid)
          | Error(_) => assertTrue("Signature verification should not fail", false)
          }
        }
      | Error(_) => assertTrue("Signing should not fail", false)
      }
    }
  | Error(_) => assertTrue("Key generation should not fail", false)
  }
}

// Run tests
testKeyGeneration()
testSignatureVerification()

// Print summary
Console.log(`Tests completed: ${Belt.Int.toString(passed.contents + failed.contents)} total, ${Belt.Int.toString(passed.contents)} passed, ${Belt.Int.toString(failed.contents)} failed\n`) 