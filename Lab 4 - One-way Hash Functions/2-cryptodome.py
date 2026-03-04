from Cryptodome.Hash import SHA256

md = SHA256.new(data=b"123")
md.update(b"456")
print(md.hexdigest())