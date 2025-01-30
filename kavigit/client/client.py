import socket
import threading
from encryption import AESEncryption
from dh_key_exchange import DiffieHellman
import hashlib

def receive_messages(client_socket, aes):
    while True:
        # Receive the message and hash
        data = client_socket.recv(2048)
        if not data:
            break

        # Split the received data into encrypted message and hash
        encrypted_data, received_hash = data.rsplit(b'\x00', 1)
        decrypted_message = aes.decrypt(encrypted_data)
        message_hash = hashlib.sha256(decrypted_message).hexdigest()

        # Verify the hash
        if message_hash == received_hash.decode('utf-8'):
            print(f"Received (encrypted): {encrypted_data}")
            print(f"Decrypted message: {decrypted_message.decode('utf-8')}")
            print(f"Message hash: {message_hash}")
            print("Hash verification successful.")
        else:
            print(f"Hash verification failed. Expected: {received_hash.decode('utf-8')}, Got: {message_hash}")

def communicate_with_server(server_address, dh):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(server_address)

    # Authentication
    response = client_socket.recv(1024).decode('utf-8')
    username = input(response)
    client_socket.sendall(username.encode('utf-8'))

    response = client_socket.recv(1024).decode('utf-8')
    password = input(response)
    client_socket.sendall(password.encode('utf-8'))

    auth_result = client_socket.recv(1024).decode('utf-8')
    print(auth_result)
    if "failed" in auth_result:
        client_socket.close()
        return 0

    # Exchange public keys
    server_public_key = int(client_socket.recv(1024).decode('utf-8').strip())
    print(f"Received server public key: {server_public_key}")

    client_public_key = dh.public_key
    print(f"Client's public key: {client_public_key}")

    client_socket.sendall(str(client_public_key).encode('utf-8'))

    shared_secret = dh.calculate_shared_secret(server_public_key)
    print(f"Calculated Shared Secret: {shared_secret}")

    aes = AESEncryption(shared_secret)

    threading.Thread(target=receive_messages, args=(client_socket, aes)).start()

    while True:
        message = input("Enter your message: ")
        encrypted_message = aes.encrypt(message.encode('utf-8'))
        message_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()
        data_to_send = encrypted_message + b'\x00' + message_hash.encode('utf-8')
        client_socket.sendall(data_to_send)
        print(f"Sent (encrypted): {encrypted_message}")
        print(f"Message hash: {message_hash}")

if __name__ == "__main__":
    dh = DiffieHellman()
    communicate_with_server(('127.0.0.1', 1194), dh)
