# CrypticW/utils.py
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from getpass import getpass
from cryptography.fernet import Fernet
import base64

# Define directories
KEYS_DIR = os.path.join(os.path.dirname(__file__), 'keys')
PRIVATE_KEY_DIR = os.path.join(KEYS_DIR, 'private_keys')
PUBLIC_KEY_DIR = os.path.join(KEYS_DIR, 'public_keys')
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
ENCRYPTED_DATA_PATH = os.path.join(os.path.dirname(__file__), 'encrypted_data.bin')

# Function to create a directory if it doesn't exist
def create_directory(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

# Generate a key pair for a user and store them
def generate_and_store_key_pair(user_id):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    create_directory(PRIVATE_KEY_DIR)
    create_directory(PUBLIC_KEY_DIR)

    private_key_path = os.path.join(PRIVATE_KEY_DIR, f'private_key_{user_id}.pem')
    public_key_path = os.path.join(PUBLIC_KEY_DIR, f'public_key_{user_id}.pem')

    with open(private_key_path, 'wb') as f:
        f.write(private_key_pem)

    with open(public_key_path, 'wb') as f:
        f.write(public_key_pem)

    return private_key_path, public_key_path

# Load a private key from a file
def load_private_key(private_key_path):
    with open(private_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        return private_key

# Load a public key from a file
def load_public_key(public_key_path):
    with open(public_key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        return public_key

# Generate a data key from a password and salt
def generate_data_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    return kdf.derive(password)

# Encrypt data using an AES-GCM cipher
def encrypt_data(data, data_key, salt):
    aesgcm = AESGCM(data_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
    return salt + nonce + ciphertext

# Decrypt data using an AES-GCM cipher
def decrypt_data(encrypted_data, data_key):
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    ciphertext = encrypted_data[28:]

    aesgcm = AESGCM(data_key)
    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_data

# Decrypt data using a private key
def private_key_decrypt(encrypted_data, private_key_path):
    private_key = load_private_key(private_key_path)
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted_data

# Retrieve and decrypt stored data for a user
def retrieve_and_decrypt_data(private_key_path, public_key_path):
    stored_information = []

    public_key = load_public_key(public_key_path)

    information_files = [f for f in os.listdir(DATA_DIR) if f.startswith('information_')]

    for info_file in information_files:
        info_file_path = os.path.join(DATA_DIR, info_file)
        with open(info_file_path, 'rb') as f:
            encrypted_data = f.read()
            data_key = private_key_decrypt(encrypted_data, private_key_path)
            decrypted_data = decrypt_data(encrypted_data, data_key)
            stored_information.append(decrypted_data.decode())

    return stored_information

# Hash a password using PBKDF2HMAC and Fernet
def hash_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return Fernet(base64.urlsafe_b64encode(key))

# Create user credentials (username, hashed password, and keys)
def create_user_credentials():
    username = input("Enter a username: ")
    print(f"Debug: Captured username: {username}")
    password = getpass("Enter a password: ")

    salt = os.urandom(16)
    fernet = hash_password(password, salt)
    hashed_password = fernet.encrypt(password.encode()).decode()

    private_key_path, public_key_path = generate_and_store_key_pair(username)  # Generate and store keys

    return username, f"{hashed_password},{base64.b64encode(salt).decode()}"