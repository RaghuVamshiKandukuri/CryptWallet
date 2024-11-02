
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Define a 16-byte key here. Use a secure key for production.
SECRET_KEY = b'securekeyhere123'

def encrypt_file(data):
    cipher = AES.new(SECRET_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

def decrypt_file(data):
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(SECRET_KEY, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
