import crypt
import hashlib

alg = 6  # SHA512


def hash_file(filename):
    h = hashlib.sha1()

    with open(filename, "rb") as file:
        chunk = 0
        while chunk != b"":
            # read only 1024 bytes at a time
            chunk = file.read(1024)
            h.update(chunk)

    return h.hexdigest()


salt = hash_file(".priv.pem")
word = input("Enter the password::")

insalt = "${}${}$".format(alg, salt)

cryptWord = crypt.crypt(word, insalt)
print(cryptWord)
