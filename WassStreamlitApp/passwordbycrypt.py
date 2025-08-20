import bcrypt
pw = "PASSWORD".encode()
print(bcrypt.hashpw(pw, bcrypt.gensalt()).decode())