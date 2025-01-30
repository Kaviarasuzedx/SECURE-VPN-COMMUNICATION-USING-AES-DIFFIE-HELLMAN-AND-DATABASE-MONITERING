from Crypto.Cipher import AES
import hashlib
import os

class AESEncryption:
    def __init__(self, key):
        self.key = hashlib.sha256(str(key).encode()).digest()
        self.iv = os.urandom(16)

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        padding_length = 16 - len(data) % 16
        data += bytes([padding_length]) * padding_length
        return self.iv + cipher.encrypt(data)

    def decrypt(self, encrypted_data):
        iv = encrypted_data[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data[16:])
        padding_length = decrypted_data[-1]
        return decrypted_data[:-padding_length]
