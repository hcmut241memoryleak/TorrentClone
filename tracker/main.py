import socket
from concurrent.futures import ThreadPoolExecutor
import json
import struct
import queue

from harbor import Harbor

TRACKER_HOST = '127.0.0.1'
TRACKER_PORT = 65432
MAX_CONNECTIONS = 16

main_thread_inbox = queue.Queue()

def send_message(harbor: Harbor, sock: socket, message):
    try:
        message_data = json.dumps(message).encode("utf-8")
        packed_data = struct.pack(">I", len(message_data)) + message_data
        sock.sendall(packed_data)
    except Exception as e:
        print(f"Error sending data to {sock.getpeername()}: {e}")
        harbor.socket_receiver_queue_remove_client_command(sock)

def main():
    executor = ThreadPoolExecutor(max_workers=5)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((TRACKER_HOST, TRACKER_PORT))
    server_socket.listen(MAX_CONNECTIONS)
    print(f"Listening on {TRACKER_HOST}:{TRACKER_PORT} for incoming peers...")

    harbor = Harbor(server_socket, main_thread_inbox)
    harbor.start()

    try:
        while True:
            try:
                message = main_thread_inbox.get(timeout=0.1)
                message_type = message[0]
                if message_type == "harbor_connection_added":
                    _, sock = message
                    print(f"Main thread: connected to {sock.getpeername()}.")

                    executor.submit(send_message, sock, "Hello from server")
                elif message_type == "harbor_connection_removed":
                    _, sock, peer_name = message
                    print(f"Main thread: connection to {peer_name} removed.")
                elif message_type == "harbor_message":
                    _, sock, msg = message
                    print(f"Main thread: message from {sock.getpeername()}: `{msg}`")
            except queue.Empty:
                continue
    except KeyboardInterrupt:
        print("Shutting down...")
        harbor.stop()

if __name__ == "__main__":
    main()