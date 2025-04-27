# encryption.py
from cryptography.fernet import Fernet

# Function to generate a secret key
def generate_key():
    key = Fernet.generate_key()
    with open('secret.key', 'wb') as key_file:
        key_file.write(key)

# Function to load the secret key from a file
def load_key():
    """Load the secret key from the 'secret.key' file"""
    return open('secret.key', 'rb').read()

# Function to encrypt a message
def encrypt_message(message):
    key = load_key()  # Load the key for encryption
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())  # Encrypt the message
    return encrypted_message


def decrypt_message(encrypted_message):
    """Decrypt the encrypted message using the secret key"""
    try:
        key = load_key()  # Load the correct secret key
        f = Fernet(key)
        decrypted_message = f.decrypt(encrypted_message)
        return decrypted_message.decode()  # Return the decrypted message as a string
    except Exception as e:
        raise ValueError("Decryption failed. Ensure the key is correct and the message is properly formatted.") from e

