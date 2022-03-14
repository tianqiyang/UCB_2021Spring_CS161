import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

backend = default_backend()

def valid_pad(plaintext):
    """Checks that `plaintext` is padded correctly"""
    try:
        PKCS7_unpad(plaintext)
        return True
    except ValueError:
        return False


def permute(plaintext, num):
    """Sets a random sequence for the first `num` elements of `plaintext`"""
    for i in range(num):
        plaintext[i] = random.getrandbits(8)
    return plaintext


def PKCS7_pad(plaintext):
    """Pad  `plaintext` following the PKCS7 standard with 16 byte blocks"""
    padder = padding.PKCS7(128).padder()
    return padder.update(plaintext) + padder.finalize()


def PKCS7_unpad(padded_plaintext):
    """Unpad `padded_plaintext` following the PKCS7 standard with 16 byte blocks.
    Throws a ValueError if the plaintext is padded incorrectly"""
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()


def CBC_decrypt(ciphertext, key):
    iv, message = ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(message) + decryptor.finalize()


def CBC_encrypt(iv, plaintext, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def D(ct):
    key = b'\xfa\x17Y\xc0\x08~(b\xec=\xce\xd5\x19N\x03;\xcab\xc7\xe3\x11\xaa\x8ct\xc4\xc4\x02\x7f\xcf)g\x08'
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    return cipher.decryptor().update(bytes(ct))


def xor_block(block1, block2):
    return [a ^ b for a, b in zip(block1, block2)]

def generate_cipher(plaintext, key, iv):
    """ helper function to generate target ciphertext """
    return CBC_encrypt(iv, PKCS7_pad(plaintext), key)

def sha256(message):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    return digest.finalize()
