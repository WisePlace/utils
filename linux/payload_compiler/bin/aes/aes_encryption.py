import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../pycryptodome"))
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)

if len(sys.argv) != 3:
    print("Usage: aes_encryption.py <input.exe> <output.enc>")
    sys.exit(1)

input_file = sys.argv[1]
output_file = sys.argv[2]

key = get_random_bytes(16)
iv = get_random_bytes(16)

with open(input_file, "rb") as f:
    data = pad(f.read())

cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted_data = cipher.encrypt(data)

with open(output_file, "wb") as f:
    f.write(encrypted_data)

with open("key_iv.h", "w") as f:
    f.write("#pragma once\n")
    f.write(f"unsigned char AES_KEY[16] = {{{', '.join(hex(b) for b in key)}}};\n")
    f.write(f"unsigned char AES_IV[16]  = {{{', '.join(hex(b) for b in iv)}}};\n")
