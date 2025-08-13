import rsa
import base64

if input("Do you want to generate keys??") in "YESyes":
    publicKey, privateKey = rsa.newkeys(2048)
    pubfile = open(".pub.pem", "x")
    privfile = open(".priv.pem", "x")
    privfile.write(privateKey.save_pkcs1().decode("utf-8"))
    pubfile.write(publicKey.save_pkcs1().decode("utf-8"))
    pubfile.close()
    privfile.close()

with open(".priv.pem", mode="rb") as privatefile:
    keydata = privatefile.read()
privateKey = rsa.PrivateKey.load_pkcs1(keydata)
with open(".pub.pem", mode="rb") as publicfile:
    keydata = publicfile.read()
publicKey = rsa.PublicKey.load_pkcs1(keydata)

if input("Do you want to encrypt text??") in "YESyes":
    message = input("Enter plaintext:")
    encMessage = base64.b64encode(rsa.encrypt(message.encode(),
                                              publicKey)).decode()
    print("encrypted text:", encMessage)

if input("Do you want to decrypt text??") in "YESyes":
    publicKey = rsa.PublicKey.load_pkcs1(keydata)
    # decMessage = rsa.decrypt((input("Enter ciphertext:")).encode(), privateKey).decode()
    decMessage = rsa.decrypt(base64.b64decode(encMessage.encode()),
                             privateKey).decode()
    print("decrypted string:", decMessage)
