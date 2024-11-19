import json
import queue
import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor

from harbor import Harbor
from peer_info import PeerInfo

TRACKER_HOST = '0.0.0.0'
TRACKER_PORT = 65432

main_thread_inbox = queue.Queue()


def send_bytes(harbor: Harbor, sock: socket.socket, socket_lock: threading.Lock, b: bytes):
    peer_name = "(broken socket)"
    try:
        peer_name = sock.getpeername()
        with socket_lock:
            sock.sendall(b)
    except Exception as e:
        print(f"Error sending data to {peer_name}: {e}")
        harbor.socket_receiver_queue_remove_client_command(sock)


def send_message(harbor: Harbor, sock: socket.socket, socket_lock: threading.Lock, tag: str, data: bytes):
    tag_bytes = tag.encode("utf-8")
    packed_data = struct.pack(">II", len(tag_bytes), len(data)) + tag_bytes + data
    send_bytes(harbor, sock, socket_lock, packed_data)


def send_json_message(harbor: Harbor, sock: socket.socket, socket_lock: threading.Lock, tag: str, message):
    try:
        json_data = json.dumps(message).encode("utf-8")
        send_message(harbor, sock, socket_lock, tag, json_data)
    except Exception as e:
        print(f"Error serializing message `{message}`: {e}")
        return


def is_localhost(ip_address: str) -> bool:
    if ip_address in ("127.0.0.1", "::1"):
        return True

    try:
        local_hostnames = [socket.gethostname(), socket.getfqdn()]
        local_ips = socket.gethostbyname_ex(socket.gethostname())[2]
        local_ips += [socket.gethostbyname(host) for host in local_hostnames]

        return ip_address in local_ips
    except socket.error:
        return False


def get_local_network_ip() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        return local_ip
    except socket.error:
        return None


def replace_localhost_with_local_ip(peer_ip: str) -> str:
    if is_localhost(peer_ip):
        local_network_ip = get_local_network_ip()
        if local_network_ip:
            return local_network_ip
    return peer_ip


class TrackerEphemeralPeerState:
    peer_name: (str, int)
    peer_info: PeerInfo
    sha256_hashes: list[str]
    send_lock: threading.Lock

    def __init__(self, peer_name: (str, int)):
        self.peer_name = peer_name
        self.peer_info = PeerInfo()
        self.sha256_hashes = []
        self.send_lock = threading.Lock()


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
                peers[sock] = TrackerEphemeralPeerState((replace_localhost_with_local_ip(peer_name[0]), peer_name[1]))

                executor.submit(send_message, harbor, sock, peers[sock].send_lock, "motd",
                                json.dumps("From central tracker: have a great day!").encode("utf-8"))
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
                                print(
                                    f"I/O thread: peer {peer_name[0]}:{peer_name[1]} announced: {len(sha256_hashes)} torrents")

                                peer_state = peers[sock]
                                if peer_state.peer_info.is_filled():
                                    other_peers = []
                                    for other_sock, other_state in peers.items():
                                        if not other_state.peer_info.is_filled():
                                            continue
                                        if other_state.peer_info.peer_id == peer_state.peer_info.peer_id:
                                            continue
                                        if not any(sha256_hash in peer_state.sha256_hashes for sha256_hash in
                                                   other_state.sha256_hashes):
                                            continue
                                        other_peers.append((other_state.peer_info.peer_id, other_state.peer_name[0],
                                                            other_state.peer_info.peer_port))
                                    if len(other_peers) > 0:
                                        executor.submit(send_json_message, harbor, sock, peers[sock].send_lock, "peers",
                                                        other_peers)
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
