let add = (a: int, b: int) => a + b

Console.log(add(1, 2))

Console.log(Crypto.generateEcKeyPair())
Console.log(Crypto.hashSHA256("Hello, World!"))

let (publicKey, privateKey) = Crypto.generateEcKeyPair()

let signature = Crypto.signData("Hello, World!", privateKey)
let isValid = Crypto.verifySignature("Hello, World!", signature, publicKey)
Console.log(isValid)