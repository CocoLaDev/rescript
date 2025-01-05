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

Console.log("Hash.res")

// Test SHA256
let testSHA256 = () => {
  let input = "Hello, World!"
  let expected = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
  
  switch Crypto.hashSHA256(input) {
  | Ok(hash) => assertTrue("SHA256: correct hash", hash == expected)
  | Error(_) => assertTrue("SHA256: should not fail", false)
  }

  switch Crypto.hashSHA256("") {
  | Ok(hash) => assertTrue("SHA256: empty string", hash != "")
  | Error(_) => assertTrue("SHA256: empty string should not fail", false)
  }
}

// Test SHA3
let testSHA3 = () => {
  let input = "Hello, World!"
  let expected = "1af17a664e3fa8e419b8ba05c2a173169df76162a5a286e0c405b460d478f7ef"
  
  switch Crypto.hashSHA3(input) {
  | Ok(hash) => assertTrue("SHA3: correct hash", hash == expected)
  | Error(_) => assertTrue("SHA3: should not fail", false)
  }

  switch Crypto.hashSHA3("") {
  | Ok(hash) => assertTrue("SHA3: empty string", hash != "")
  | Error(_) => assertTrue("SHA3: empty string should not fail", false)
  }
}

// Run tests
testSHA256()
testSHA3()

// Print summary
Console.log(`Tests completed: ${Belt.Int.toString(passed.contents + failed.contents)} total, ${Belt.Int.toString(passed.contents)} passed, ${Belt.Int.toString(failed.contents)} failed\n`)