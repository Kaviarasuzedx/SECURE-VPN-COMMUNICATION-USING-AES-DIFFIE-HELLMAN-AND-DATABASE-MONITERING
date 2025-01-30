import socket
import threading
import sqlite3
from encryption import AESEncryption
from dh_key_exchange import DiffieHellman
import hashlib

# user database
USER_DB = {
    "kaviarasu": "kaviarasu",
    "santhru": "santa",
}

DATABASE = 'vpn_project.db'

def log_client_connection(address):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('INSERT INTO clients (address) VALUES (?)', (str(address),))
    conn.commit()
    client_id = c.lastrowid
    conn.close()
    return client_id

def log_message(client_id, message, message_hash, is_received):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('INSERT INTO messages (client_id, message, message_hash, is_received) VALUES (?, ?, ?, ?)',
              (client_id, message, message_hash, is_received))
    conn.commit()
    conn.close()

def authenticate_user(client_socket):
    client_socket.sendall(b"Enter username: ")
    username = client_socket.recv(1024).decode('utf-8').strip()

    client_socket.sendall(b"Enter password: ")
    password = client_socket.recv(1024).decode('utf-8').strip()

    if username in USER_DB and USER_DB[username] == password:
        client_socket.sendall(b"Authentication successful\n")
        return True
    else:
        client_socket.sendall(b"Authentication failed\n")
        return False

def handle_client(client_socket, dh):
    try:
        client_id = log_client_connection(client_socket.getpeername())

        if not authenticate_user(client_socket):
            client_socket.close()
            return

        # Exchange public keys
        client_socket.sendall(str(dh.public_key).encode('utf-8'))
        client_public_key = int(client_socket.recv(1024).decode('utf-8').strip())
        shared_secret = dh.calculate_shared_secret(client_public_key)

        print(f"Client's Public Key (int): {client_public_key}")
        print(f"Server's Public Key (int): {dh.public_key}")
        print(f"Calculated Shared Secret: {shared_secret}")

        aes = AESEncryption(shared_secret)

        while True:
            data = client_socket.recv(2048)
            if not data:
                break

            encrypted_data, received_hash = data.rsplit(b'\x00', 1)
            decrypted_message = aes.decrypt(encrypted_data)
            message_hash = hashlib.sha256(decrypted_message).hexdigest()

            if message_hash == received_hash.decode('utf-8'):
                print(f"Received (encrypted): {encrypted_data}")
                print(f"Decrypted message: {decrypted_message.decode('utf-8')}")
                print(f"Message hash: {message_hash}")
                print("Hash verification successful.")
                log_message(client_id, decrypted_message.decode('utf-8'), message_hash, is_received=True)
            else:
                print(f"Hash verification failed. Expected: {received_hash.decode('utf-8')}, Got: {message_hash}")

            response = input("Enter your message: ")
            encrypted_response = aes.encrypt(response.encode('utf-8'))
            response_hash = hashlib.sha256(response.encode('utf-8')).hexdigest()
            data_to_send = encrypted_response + b'\x00' + response_hash.encode('utf-8')
            client_socket.sendall(data_to_send)
            print(f"Sent (encrypted): {encrypted_response}")
            print(f"Response hash: {response_hash}")
            log_message(client_id, response, response_hash, is_received=False)

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client_socket.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 1194))
    server_socket.listen(5)
    print("Server Is Ready To Host 1194")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from: {addr}")
        dh = DiffieHellman()
        threading.Thread(target=handle_client, args=(client_socket, dh)).start()

if __name__ == "__main__":
    start_server()
