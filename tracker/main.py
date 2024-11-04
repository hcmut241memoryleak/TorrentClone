import socket
from concurrent.futures import ThreadPoolExecutor
import json
import struct
import queue

from harbor import Harbor
from peer_info import PeerInfo

TRACKER_HOST = '127.0.0.1'
TRACKER_PORT = 65432

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

    peers: dict[socket.socket, PeerInfo] = {}

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((TRACKER_HOST, TRACKER_PORT))
    server_socket.listen()
    print(f"I/O thread: listening on {TRACKER_HOST}:{TRACKER_PORT} for incoming peers...")

    harbor = Harbor(server_socket, main_thread_inbox)
    harbor.start()

    stop_requested = False
    keep_running = True
    while keep_running:
        try:
            message = main_thread_inbox.get(timeout=0.1)
            message_type = message[0]
            if message_type == "harbor_connection_added":
                _, sock, peer_name = message
                print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} connected.")
                executor.submit(send_message, harbor, sock, ("motd", "From central tracker: have a great day!"))

                peers[sock] = PeerInfo()
            elif message_type == "harbor_connection_removed":
                _, sock, peer_name, caused_by_stop = message
                print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} disconnected.")

                del peers[sock]
            elif message_type == "harbor_message":
                _, sock, peer_name, msg = message
                try:
                    msg_command_type = msg[0]
                    if msg_command_type == "peer_info":
                        _, json_info = msg
                        if sock in peers:
                            info = PeerInfo.from_dict(json.loads(json_info))
                            peers[sock] = info
                            print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} sent info: {info}")
                    else:
                        print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} sent: {msg}")
                except Exception as e:
                    print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} sent malformed message: {e}")
            elif message == "harbor_stopped":
                print(f"I/O thread: Harbor stopped.")
                keep_running = False
        except queue.Empty:
            continue
        except KeyboardInterrupt:
            stop_requested = True

        if stop_requested:
            stop_requested = False
            print("I/O thread: stopping Harbor...")
            harbor.stop()

    executor.shutdown()
    print("I/O thread: bye")

if __name__ == "__main__":
    main()