import socket
from concurrent.futures import ThreadPoolExecutor
import json
import struct
import queue

from harbor import Harbor

TRACKER_HOST = '127.0.0.1'
TRACKER_PORT = 65432
PEER_HOST = '127.0.0.1'
PEER_PORT = 65433

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
    server_socket.bind((PEER_HOST, PEER_PORT))
    server_socket.listen()
    print(f"Main thread: listening on {PEER_HOST}:{PEER_PORT} for other peers...")

    harbor = Harbor(server_socket, main_thread_inbox)
    harbor.start()

    tracker_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tracker_sock.connect((TRACKER_HOST, TRACKER_PORT))
    print(f"Main thread: connected to tracker {TRACKER_HOST}:{TRACKER_PORT}. Adding to Harbor.")
    harbor.socket_receiver_queue_add_client_command(tracker_sock)

    while True:
        try:
            message = main_thread_inbox.get(timeout=0.1)
            message_type = message[0]
            if message_type == "harbor_connection_added":
                _, sock = message
                print(f"Main thread: connected to {sock.getpeername()}.")

                if sock == tracker_sock:
                    executor.submit(send_message, harbor, sock, "From peer: hello tracker!")
            elif message_type == "harbor_connection_removed":
                _, sock, peer_name = message
                print(f"Main thread: disconnected from {peer_name}.")
            elif message_type == "harbor_message":
                _, sock, msg = message
                print(f"Main thread: message from {sock.getpeername()}: `{msg}`")
        except queue.Empty:
            continue
        except KeyboardInterrupt:
            break

    print("Shutting down...")
    harbor.stop()
    executor.shutdown()
    print("Shut down successfully.")

if __name__ == "__main__":
    main()