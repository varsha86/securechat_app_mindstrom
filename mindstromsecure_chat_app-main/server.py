import socket
import threading
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Generate EC key pair
server_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
server_public_key = server_private_key.public_key()

# Store clients and their derived keys
clients = {}

def encrypt_message(key, plaintext):
    iv = os.urandom(16)
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

def authenticate_client(client_socket):
    credentials = client_socket.recv(1024)
    username, password = credentials.split(b':')
    # In a real system, fetch the hashed password from a database and compare
    print(f"Authenticating {username.decode()}")
    return True  # Simplified for demo

def handle_client(client_socket):
    try:
        if not authenticate_client(client_socket):
            print("Authentication failed.")
            client_socket.close()
            return

        # Send server's public key
        server_public_pem = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.sendall(server_public_pem)

        # Receive client's public key
        client_public_pem = client_socket.recv(1024)
        client_public_key = serialization.load_pem_public_key(client_public_pem, backend=default_backend())

        # Perform key exchange
        shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)

        # Derive a symmetric key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'chat_app',
            backend=default_backend()
        ).derive(shared_key)

        print(f"Shared key: {derived_key.hex()}")

        clients[client_socket] = derived_key

        while True:
            data = client_socket.recv(1024)
            if not data:
                break

            # Split message and HMAC
            encrypted_message = data[:-32]  # Assume last 32 bytes are HMAC
            received_hmac = data[-32:]

            # Verify HMAC
            if received_hmac != hmac_message(derived_key, encrypted_message):
                print("HMAC verification failed!")
                continue

            # Decrypt the message
            message = decrypt_message(derived_key, encrypted_message)
            print(f"Received: {message.decode()}")

            # Broadcast the message to other clients
            broadcast_message(encrypted_message, client_socket)

    except Exception as e:
        print(f"Client handling error: {e}")
    finally:
        client_socket.close()

def broadcast_message(message, sender_socket):
    for client_socket in clients.keys():
        if client_socket != sender_socket:
            client_socket.sendall(message)

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 9999))
    server.listen(5)
    print("Server listening on port 9999...")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_server()
