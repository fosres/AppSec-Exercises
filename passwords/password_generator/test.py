import nacl.utils

byte_arr = nacl.utils.random(1)

integer = int.from_bytes(byte_arr,"big")

print(integer)
