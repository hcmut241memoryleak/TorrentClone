import socket
from time import sleep

import select
import threading
from concurrent.futures import ThreadPoolExecutor
import json
import struct

# Set up server constants
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432
MAX_CONNECTIONS = 10

# Dictionary to hold client connections
clients = {}

# Function to handle incoming messages
def handle_incoming_data(sock):
    try:
        # Receive the message length
        raw_msg_len = sock.recv(4)
        if not raw_msg_len:
            return False  # Connection closed
        msg_len = struct.unpack('>I', raw_msg_len)[0]

        # Receive the message data
        data = b""
        while len(data) < msg_len:
            packet = sock.recv(msg_len - len(data))
            if not packet:
                return False
            data += packet

        # Parse the JSON data
        json_data = json.loads(data.decode('utf-8'))
        print(f"Received data from {sock.getpeername()}: {json_data}")
        return True

    except Exception as e:
        print(f"Error handling data from {sock.getpeername()}: {e}")
        return False

# Receiving thread using select to monitor all sockets
def receiving_thread():
    while True:
        if len(clients) == 0:
            sleep(0.5)
            continue

        # Monitor all sockets for readability
        readable_socks, _, _ = select.select(list(clients.keys()), [], [])
        for sock in readable_socks:
            if not handle_incoming_data(sock):
                # If False is returned, the client has disconnected
                print(f"Client {sock.getpeername()} disconnected.")
                sock.close()
                del clients[sock]

# Function to send a message using a worker thread
def send_message(sock, message):
    try:
        message_data = json.dumps(message).encode('utf-8')
        packed_data = struct.pack('>I', len(message_data)) + message_data
        sock.sendall(packed_data)
        print(f"Sent data to {sock.getpeername()}: {message}")
    except Exception as e:
        print(f"Error sending data to {sock.getpeername()}: {e}")
        sock.close()
        del clients[sock]

# Main server loop to accept new connections
def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(MAX_CONNECTIONS)
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}...")

    # Start the receiving thread
    threading.Thread(target=receiving_thread, daemon=True).start()

    # Thread pool for sending messages
    with ThreadPoolExecutor(max_workers=5) as executor:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Accepted connection from {client_address}")
            clients[client_socket] = client_address

            # Example usage: Send a welcome message
            welcome_message = {'command': 'welcome', 'payload': 'Hello, client!'}
            executor.submit(send_message, client_socket, welcome_message)

if __name__ == "__main__":
    main()