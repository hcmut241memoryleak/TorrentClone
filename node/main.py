import socket
from concurrent.futures import ThreadPoolExecutor
import json
import struct
import queue

from harbor import Harbor
from peer_data import generate_unique_id, PeerData

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
    my_peer_id = generate_unique_id()
    print(f"Main thread: ID is {my_peer_id}")

    executor = ThreadPoolExecutor(max_workers=5)

    peers: dict[socket.socket, PeerData] = {}

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

    stop_requested = False
    keep_running = True
    while keep_running:
        try:
            message = main_thread_inbox.get(timeout=0.1)
            message_type = message[0]
            if message_type == "harbor_connection_added":
                _, sock, peer_name = message
                if sock == tracker_sock:
                    print(f"Main thread: connected to tracker {peer_name[0]}:{peer_name[1]}. Sending ID.")
                    executor.submit(send_message, harbor, sock, ("peer_id", my_peer_id))
                else:
                    print(f"Main thread: connected to peer {peer_name[0]}:{peer_name[1]}.")
            elif message_type == "harbor_connection_removed":
                _, sock, peer_name, caused_by_stop = message
                if sock == tracker_sock:
                    print(f"Main thread: disconnected from tracker {peer_name[0]}:{peer_name[1]}! Stopping.")
                    if not caused_by_stop:
                        stop_requested = True
            elif message_type == "harbor_message":
                _, sock, peer_name, msg = message
                if sock == tracker_sock:
                    msg_command_type = msg[0]
                    if msg_command_type == "motd":
                        _, motd = msg
                        print(f"Main thread: MOTD from tracker {peer_name[0]}:{peer_name[1]}: {motd}")
                    else:
                        print(f"Main thread: message from tracker {peer_name[0]}:{peer_name[1]}: {msg}")
                else:
                    print(f"Main thread: message from peer {peer_name[0]}:{peer_name[1]}: {msg}")
            elif message == "harbor_stopped":
                print(f"Main thread: Harbor stopped.")
                keep_running = False
        except queue.Empty:
            continue
        except KeyboardInterrupt:
            stop_requested = True

        if stop_requested:
            stop_requested = False
            print("Main thread: stopping Harbor...")
            harbor.stop()

    executor.shutdown()
    print("Main thread: bye")

if __name__ == "__main__":
    main()