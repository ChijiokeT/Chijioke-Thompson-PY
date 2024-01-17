from flask import Flask, request, send_file
import os
import zipfile
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

app = Flask(__name__)
# Function to generate an RSA key pair (private and public keys)
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
    elif isinstance(key, rsa.RSAPublicKey):
        with open(filename, "wb") as key_file:
            key_file.write(key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    else:
        raise ValueError("Unsupported key type")

# Function to load a private key from a PEM file
def load_key_from_file(filename, passphrase=None):
    # Load a private key from a PEM file, with optional passphrase
    with open(filename, "rb") as key_file:
        key_data = key_file.read()
        if passphrase is None:
            return serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
        else:
            return serialization.load_pem_private_key(key_data, password=passphrase.encode('utf-8'), backend=default_backend())

# Function to decrypt a message using RSA-OAEP with SHA-256
def decrypt_message_rsa(encrypted_message, private_key):
    try:
        # Convert the hexadecimal representation of the encrypted message to bytes
        encrypted_data = bytes.fromhex(encrypted_message)

        # Check if the length of the encrypted data is consistent with the key size
        key_size_bytes = private_key.key_size // 8
        if len(encrypted_data) != key_size_bytes:
            raise ValueError("Ciphertext length does not match key size")

        # Decrypt the message
        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Convert the decrypted data to a string
        decrypted_message = decrypted_data.decode('utf-8')

        return decrypted_message
    except ValueError as ve:
        print(f"Error decrypting message: {str(ve)}")
        return f'Error decrypting message: {str(ve)}'
    except Exception as e:
        print(f"Error decrypting message: {str(e)}")
        return 'Error decrypting message.'

# Create a folder to store backup messages
if not os.path.exists("backup_messages"):
    os.makedirs("backup_messages")

# Generate and save keys for User 2 with passphrase
user2_private_key, user2_public_key = generate_rsa_key_pair()
user2_passphrase = "your_secure_passphrase"  # Replace with a strong passphrase
save_key_to_file(user2_private_key, ".env/user2_private_key.pem", passphrase=user2_passphrase)
save_key_to_file(user2_public_key, ".env/user2_public_key.pem")

# Counter to generate unique filenames

message_counter = 1
# Route to receive encrypted messages via HTTP POST
@app.route('/receive_message', methods=['POST'])
def receive_message():
    global message_counter 
    encrypted_message = request.form['message']
    
    # Load private key securely using passphrase
    user2_private_key_loaded = load_key_from_file(".env/user2_private_key.pem", passphrase=user2_passphrase)
    try:
        # Decrypt the received message
         # Decrypt the received message
        decrypted_message = decrypt_message_rsa(encrypted_message, user2_private_key_loaded)

        # Save each decrypted and encrypted message in a separate file
        decrypted_filename = f"backup_messages/decrypted_message_{message_counter}.txt"
        # encrypted_filename = f"backup_messages/encrypted_message_{message_counter}.txt"
        
        with open(decrypted_filename, "w") as decrypted_file:
            decrypted_file.write(decrypted_message)
        
        # with open(encrypted_filename, "w") as encrypted_file:
        #     encrypted_file.write(encrypted_message)
        
        # Now zip the encrypted message file
        with zipfile.ZipFile(f"backup_messages/decrypted_message_{message_counter}.zip", "w") as zip_file:
            zip_file.write(decrypted_filename)
        
        print(f"User 2 received message: {decrypted_message}")
        print(f"user1 message encryption : {encrypted_message}")
        
        # Increment the counter for the next message
        
        message_counter += 1
        
        return 'Message received successfully.'
    except Exception as e:
        print(f"Error decrypting message: {str(e)}")
        return 'Error decrypting message.'

# Route to create a zip archive containing backup messages
@app.route('/create_backup_zip')
def create_backup_zip():
    try:
        # Create a zip archive containing all backup messages
        zip_filename = "backup_messages.zip"
        with zipfile.ZipFile(zip_filename, "w") as zip_file:
            for root, _, files in os.walk("backup_messages"):
                for file in files:
                    file_path = os.path.join(root, file)
                    zip_file.write(file_path, os.path.relpath(file_path, "backup_messages"))

        return send_file(zip_filename, as_attachment=True)
    except Exception as e:
        print(f"Error creating zip archive: {str(e)}")
        return 'Error creating zip archive.'

# Run the Flask application on port 7000
if __name__ == '__main__':
    app.run(port=7000)
