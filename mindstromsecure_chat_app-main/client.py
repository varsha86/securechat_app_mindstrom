import socket
import hashlib
import hmac
import os
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Generate EC key pair
client_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
client_public_key = client_private_key.public_key()

def encrypt_message(key, plaintext):
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext

def hmac_message(key, message):
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message)
    return h.finalize()

def start_client():
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("localhost", 9999))
        print("Connected to server.")

        # Authenticate the user
        username = input("Username: ").encode()
        password = getpass("Password: ").encode()

        # Send username and hashed password to server for authentication
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        hashed_password = kdf.derive(password)
        client.sendall(username + b':' + hashed_password)

        # Send client's public key after successful authentication
        client_public_pem = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client.sendall(client_public_pem)

        # Receive server's public key
        server_public_pem = client.recv(1024)
        server_public_key = serialization.load_pem_public_key(server_public_pem, backend=default_backend())

        # Perform key exchange
        shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)

        # Derive a symmetric key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'chat_app',
            backend=default_backend()
        ).derive(shared_key)

        print(f"Shared key: {derived_key.hex()}")

        while True:
            message = input("Enter message: ").encode()
            if message.lower() == b"exit":
                break

            # Encrypt the message with AES
            encrypted_message = encrypt_message(derived_key, message)

            # Add HMAC for integrity check
            hmac_tag = hmac_message(derived_key, encrypted_message)

            # Send the encrypted message and HMAC
            client.sendall(encrypted_message + hmac_tag)

    except Exception as e:
        print(f"Connection error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    start_client()
