from cryptography.fernet import Fernet

# Load the secret key
def load_key():
    return open('secret.key', 'rb').read()

# Decrypt a message
def decrypt_message(encrypted_message):
    key = load_key()  # Load the secret key
    fernet = Fernet(key)  # Create a Fernet object with the key
    try:
        decrypted_message = fernet.decrypt(encrypted_message).decode()  # Decrypt the message
        return decrypted_message
    except Exception as e:
        return f"Decryption Failed! Error: {str(e)}"

# Test decryption
if __name__ == "__main__":
    encrypted_message = b'gAAAAABoDUqz7Zzi8nXdopSupd2n2E6Ug7GjszwlqyabQUzRjTh1eUVLMebk09SmwxCzjzMDdvp6VZS5LXLzVXN2tpRksAMRuA=='
    decrypted = decrypt_message(encrypted_message)  # Decrypt the message
    print(f"Decrypted message: {decrypted}")
