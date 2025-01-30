import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_parameters, load_pem_private_key
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from Crypto.Util import number

import random


class DiffieHellman:
    def __init__(self, p=23, g=5):
        self.p = p  # Prime number
        self.g = g  # Primitive root modulo p
        self.private_key = random.randint(1, p - 1)
        self.public_key = pow(g, self.private_key, self.p)

    def calculate_shared_secret(self, other_public_key):
        """
        Calculate the shared secret using the other party's public key.
        """
        shared_secret = pow(other_public_key, self.private_key, self.p)
        return shared_secret
