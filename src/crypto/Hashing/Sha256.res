let sha256 = (data: string): string => {
  let hash = Hashing.createHash("sha256")
  hash->Hashing.update(data)->Hashing.digest("hex")
}
