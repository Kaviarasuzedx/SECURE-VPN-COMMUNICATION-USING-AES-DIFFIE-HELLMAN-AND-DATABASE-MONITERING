# client/encryption.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def encrypt_message(message, key):
    iv = os.urandom(16)  # Initialization Vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_message = iv + encryptor.update(message.encode()) + encryptor.finalize()
    return encrypted_message
