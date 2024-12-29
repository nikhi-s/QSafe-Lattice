from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Function to generate an RSA public-private key pair
def generate_rsa_key_pair(key_size):
    """
    Generates an RSA key pair (private and public keys).

    RSA (Rivest-Shamir-Adleman) is a public-key cryptosystem that is widely used
    for secure data transmission. This function generates both a private key and
    a public key.

    Args:
    key_size (int): The size of the key, typically 2048 or 4096 bits. Larger key sizes
                    provide better security but are computationally more expensive.

    Returns:
    private_key (rsa.RSAPrivateKey): The generated RSA private key.
    public_key (rsa.RSAPublicKey): The corresponding RSA public key derived from
                                   the private key.

    Steps:
    1. The `rsa.generate_private_key` function generates a private key. The key size
       determines how secure the key is. The public exponent `65537` is a standard value
       widely used for RSA, as it provides a good balance between security and performance.

    2. The public key is extracted from the generated private key using the
       `private_key.public_key()` method.

    3. Both the private and public keys are returned, which can be used for encryption
       (public key) and decryption (private key), or for signing (private key) and
       verification (public key).
    """
    # Step 1: Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Common choice for public exponent e
        key_size=key_size,      # Key Size for legitimate encryption (typically 2048 or 4096)
        backend=default_backend()  # Use the default backend for cryptography operations
    )

    # Extract public key from the private key
    public_key = private_key.public_key()

    # Returning both the private and public keys
    return private_key, public_key

# Serialize the keys
def serialize_key(key, is_private=True):
    """
    Serializes an RSA key (either private or public) to PEM format.

    Parameters:
    key (PrivateKey or PublicKey): The RSA key object to be serialized.
    is_private (bool): Flag indicating whether the key is private or public.
                       - If True (default), serializes the private key.
                       - If False, serializes the public key.

    Returns:
    bytes: The serialized key in PEM format.

    Details:
    - Private keys are serialized in the TraditionalOpenSSL format without encryption.
      This means the private key will not be password protected, which can be useful
      for development but should be handled carefully in production environments.

    - Public keys are serialized in the SubjectPublicKeyInfo format, which is a
      standard format for public keys.

    The serialized key is returned as bytes, which can be written to a file or used
    in other operations that require the PEM format.

    Example Usage:
    - To serialize a private key:
        private_pem = serialize_key(private_key, is_private=True)

    - To serialize a public key:
        public_pem = serialize_key(public_key, is_private=False)
    """

    if is_private:
        # Serialize the private key to PEM format
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,  # PEM format (Base64 encoded)
            format=serialization.PrivateFormat.TraditionalOpenSSL,  # OpenSSL format for private keys
            encryption_algorithm=serialization.NoEncryption()  # No password protection
        )
    else:
        # Serialize the public key to PEM format
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,  # PEM format
            format=serialization.PublicFormat.SubjectPublicKeyInfo  # Standard public key format
        )

# Encrypt a message using RSA public key encryption
def encrypt_message(message, public_key):
    """
    Encrypts a given message using the provided RSA public key.

    Args:
        message (bytes): The plaintext message to be encrypted. The message must be in bytes.
        public_key (RSAPublicKey): The RSA public key used for encryption.

    Returns:
        bytes: The encrypted message (ciphertext) in bytes.

    Details:
        This function uses RSA encryption with Optimal Asymmetric Encryption Padding (OAEP)
        to securely encrypt the message. OAEP is a padding scheme used with RSA to ensure that
        the encrypted data is secure and resistant to various types of cryptographic attacks.

        OAEP uses a Mask Generation Function (MGF1) based on SHA-256 to create the padding.
        Additionally, SHA-256 is used as the hashing algorithm within the padding itself.
        The `label` parameter is left as `None` since no label is being used in this context.

        The resulting encrypted message is returned as a byte string, which can then be
        safely transmitted or stored.

    Example:
        message = b"Hello, RSA encryption!"
        encrypted_message = encrypt_message(message, public_key)
        print(encrypted_message)

    Raises:
        TypeError: If the message is not in bytes format.
    """

    # Encrypt the message using the public key and OAEP padding
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask Generation Function with SHA-256
            algorithm=hashes.SHA256(),  # Hash algorithm for OAEP padding
            label=None  # No label used
        )
    )

    return encrypted_message

# Decrypt a message
def decrypt_message(encrypted_message, private_key):
    """
    Decrypts an encrypted message using the provided RSA private key.

    This function uses the OAEP (Optimal Asymmetric Encryption Padding) scheme with SHA-256 for secure decryption.
    The private key is used to decrypt the ciphertext and retrieve the original plaintext message.

    Args:
        encrypted_message (bytes): The encrypted message (ciphertext) that needs to be decrypted.
                                   This is the result of RSA encryption.
        private_key (RSAPrivateKey): The private key used for decryption. This should be an RSA private key
                                     generated using the RSA algorithm.

    Returns:
        bytes: The decrypted message (plaintext) as bytes.

    Example:
        decrypted_message = decrypt_message(ciphertext, private_key)
        print(decrypted_message.decode())  # Convert the decrypted bytes to a string
    """

    # Perform decryption using the RSA private key with OAEP padding
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask Generation Function with SHA-256
            algorithm=hashes.SHA256(),                    # Hash function for OAEP
            label=None                                    # Optional label, usually left as None
        )
    )

    # Return the decrypted message (plaintext)
    return decrypted_message
