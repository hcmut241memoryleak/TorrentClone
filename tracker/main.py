import json
import queue
import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor

from harbor import Harbor
from node.torrenting import TrackerEphemeralPeerState
from peer_info import PeerInfo

TRACKER_HOST = '127.0.0.1'
TRACKER_PORT = 65432

main_thread_inbox = queue.Queue()


def send_bytes(harbor: Harbor, sock: socket, socket_lock: threading.Lock, b: bytes):
    peer_name = "(broken socket)"
    try:
        peer_name = sock.getpeername()
        with socket_lock:
            sock.sendall(b)
    except Exception as e:
        print(f"Error sending data to {peer_name}: {e}")
        harbor.socket_receiver_queue_remove_client_command(sock)


def send_message(harbor: Harbor, sock: socket, socket_lock: threading.Lock, message):
    try:
        json_message = json.dumps(message).encode("utf-8")
        packed_data = struct.pack(">I", len(json_message)) + json_message
        send_bytes(harbor, sock, socket_lock, packed_data)
    except Exception as e:
        print(f"Error serializing message `{message}`: {e}")
        return


def main():
    executor = ThreadPoolExecutor(max_workers=5)

    peers: dict[socket.socket, TrackerEphemeralPeerState] = {}

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
                peers[sock] = TrackerEphemeralPeerState(peer_name)

                executor.submit(send_message, harbor, sock, peers[sock].send_lock, ("motd", "From central tracker: have a great day!"))
            elif message_type == "harbor_connection_removed":
                _, sock, peer_name, caused_by_stop = message
                print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} disconnected.")

                del peers[sock]
            elif message_type == "harbor_message":
                _, sock, peer_name, tag, msg = message
                try:
                    if tag == "peer_info":
                        if sock in peers:
                            try:
                                info = PeerInfo.from_dict(json.loads(msg.decode("utf-8")))
                                peers[sock].peer_info = info
                                print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} sent info: {info}")
                            except Exception as e:
                                pass
                    elif tag == "peer_torrent_list":
                        if sock in peers:
                            try:
                                sha256_hashes = json.loads(msg.decode("utf-8"))
                                peers[sock].sha256_hashes = sha256_hashes
                                print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} announced: {len(sha256_hashes)} torrents")
                            except Exception as e:
                                pass
                    else:
                        print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} sent: {msg}")
                except Exception as e:
                    print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} sent malformed message: {e}")
            elif message == "harbor_stopped":
                keep_running = False
        except queue.Empty:
            continue
        except KeyboardInterrupt:
            stop_requested = True

        if stop_requested:
            stop_requested = False
            harbor.stop()

    executor.shutdown()


if __name__ == "__main__":
    main()
