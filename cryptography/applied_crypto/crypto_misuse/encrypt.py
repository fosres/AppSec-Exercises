import nacl.secret
import nacl.utils

mess = 'warn'

mess = mess.encode()

key=nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

box=nacl.secret.SecretBox(key)

encrypted = box.encrypt(mess)

print(f"encrypted:{encrypted}")

decrypted = box.decrypt(encrypted)

print(f"decrypted:{decrypted}")

