"""
rsa_implementation.py

Core RSA key generation, serialization, encryption, and decryption helpers
used by benchmark_rsa.py and main.py.

NOTE ON FILENAME: this module was previously named RSA_Implementation.py.
It has been renamed to lowercase (rsa_implementation.py) because Python
module names are conventionally lowercase, and because the old mixed-case
filename combined with a lowercase `from rsa_implementation import ...`
in main_rsa-test caused an ImportError on case-sensitive filesystems
(Linux, macOS default in some configs, GitHub Actions, Google Colab),
even though it worked by accident on case-insensitive Windows filesystems.
If you keep the old filename, update every import to match it exactly.
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def generate_rsa_key_pair(key_size: int):
    """
    Generate an RSA key pair.

    Args:
        key_size: RSA key size in bits (e.g. 1024, 2048, 3072, 4096, 8192).

    Returns:
        (private_key, public_key) tuple.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_key(key, is_private: bool = True) -> bytes:
    """Serialize an RSA key to PEM format."""
    if is_private:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def max_oaep_plaintext_bytes(key_size_bits: int, hash_len_bytes: int = 32) -> int:
    """
    Return the maximum plaintext length (bytes) that RSA-OAEP can encrypt
    for a given key size and hash function.

    Formula (RFC 8017): max = k - 2*hLen - 2, where k = key size in bytes.
    Default hash_len_bytes=32 matches SHA-256, used in encrypt_message below.
    """
    k = key_size_bits // 8
    return k - 2 * hash_len_bytes - 2


def encrypt_message(message: bytes, public_key) -> bytes:
    """Encrypt `message` (bytes) with RSA-OAEP (SHA-256 / MGF1-SHA256)."""
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_message(encrypted_message: bytes, private_key) -> bytes:
    """Decrypt `encrypted_message` (bytes) with RSA-OAEP (SHA-256 / MGF1-SHA256)."""
    return private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
