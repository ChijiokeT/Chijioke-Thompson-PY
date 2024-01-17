from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import requests
import os
import shutil
import zipfile

if not os.path.exists(".env"):
    os.makedirs(".env")

# Function to generate RSA key pair (private and public keys)
def generate_rsa_key_pair():
    # Generate a private key and its corresponding public key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    return private_key, public_key

# Function to save an RSA key (private or public) to a PEM file
def save_key_to_file(key, filename, passphrase=None):
    # Save the key to a file in PEM format, with optional passphrase for extra security
    if isinstance(key, rsa.RSAPrivateKey):
        encryption_algorithm = (
            serialization.NoEncryption() if passphrase is None
            else serialization.BestAvailableEncryption(passphrase.encode('utf-8'))
        )
        with open(filename, "wb") as key_file:
            key_file.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            ))
        # Set strict file permissions for private key
        os.chmod(filename, 0o600)
    elif isinstance(key, rsa.RSAPublicKey):
        with open(filename, "wb") as key_file:
            key_file.write(key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    else:
        raise ValueError("Unsupported key type")

# Function to load a private key from a PEM file
def load_private_key_from_file(filename, passphrase=None):
    # Load a private key from a PEM file, with optional passphrase
    with open(filename, "rb") as key_file:
        key_data = key_file.read()
        if passphrase is None:
            return serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
        else:
            return serialization.load_pem_private_key(key_data, password=passphrase.encode('utf-8'), backend=default_backend())

# Function to load a public key from a PEM file
def load_public_key_from_file(filename):
    # Load a public key from a PEM file
    with open(filename, "rb") as key_file:
        key_data = key_file.read()
        return serialization.load_pem_public_key(key_data, backend=default_backend())

# Function to encrypt a message using RSA-OAEP with SHA-256
def encrypt_message_rsa(message, public_key):
    # Encrypt the message using RSA-OAEP with SHA-256
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

# Function to send an encrypted message to a recipient
def send_message(message, recipient_public_key_file, sender_private_key_file, passphrase=None):
    try:
        # Load public key of the recipient
        recipient_public_key = load_public_key_from_file(recipient_public_key_file)

        # Load private key of the sender
        sender_private_key = load_private_key_from_file(sender_private_key_file, passphrase)

        # Encrypt the message with recipient's public key
        encrypted_message = encrypt_message_rsa(message, recipient_public_key)

        # Send the encrypted message directly to the recipient
        payload = {'message': encrypted_message.hex()}  # Convert bytes to hexadecimal for transmission
        response = requests.post('http://127.0.0.1:7000/receive_message', data=payload)
        print(response.text)

    except Exception as e:
        print(f"Error sending message: {str(e)}")



# Generate key pair for User 1
user1_private_key, user1_public_key = generate_rsa_key_pair()

# Save keys securely with a passphrase for User 1
user1_passphrase = "your_secure_passphrase"  # Replace with a strong passphrase
save_key_to_file(user1_private_key, ".env/user1_private_key.pem", passphrase=user1_passphrase)
save_key_to_file(user1_public_key, ".env/user1_public_key.pem")

# Specify the public key file for User 2
recipient_public_key_file = ".env/user2_public_key.pem"
# Specify the private key file for User 2
recipient_private_key_file = ".env/user2_private_key.pem"

# # Check if the private key file for User 2 exists
# if not os.path.exists(recipient_private_key_file):
#     # If not, generate a new key pair for User 2
#     print("Private key file for User 2 does not exist. Generating a new key pair...")
#     user2_private_key, user2_public_key = generate_rsa_key_pair()
#     # Save keys for User 2
#     save_key_to_file(user2_private_key, recipient_private_key_file)
#     save_key_to_file(user2_public_key, recipient_public_key_file)

# Main loop for User 1 to send messages
while True:
    # Get a message from User 1
    message = input("User 1, enter your message (or type 'exit' to end): ")
    if message.lower() == 'exit':
        break
    # Send the message to User 2
    send_message(message, recipient_public_key_file, recipient_private_key_file, passphrase=user1_passphrase)
