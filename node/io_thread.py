import json
import os
import queue
import socket
import struct
from concurrent.futures import ThreadPoolExecutor

from PyQt6.QtCore import QThread, pyqtSignal

from harbor import Harbor
from hashing import base62_sha1_hash_of
from node.torrenting import LiveTorrent
from peer_info import generate_unique_id, PeerInfo
from torrent_data import TorrentFile, pack_files_to_pieces, Piece, Torrent

TARGET_TRACKER_HOST = '127.0.0.1'
TARGET_TRACKER_PORT = 65432

PEER_HOST = '127.0.0.1'
PEER_PORT = 65433

# def file_path_to_torrent_file(path: str):
#     TorrentFile(path, os.path.getsize(path))

def files_from_path(base_path: str):
    if os.path.isfile(base_path):
        new_base_path = os.path.dirname(base_path)
        return new_base_path, [os.path.relpath(base_path, new_base_path)]

    file_paths = []
    for root, dirs, files in os.walk(base_path):
        for file in files:
            file_paths.append(os.path.relpath(str(os.path.join(root, file)), base_path)) # TODO: why str()?
    return base_path, file_paths

def initiate_piece_hashes(base_path: str, files: list[TorrentFile], pieces: list[Piece], piece_size: int):
    for piece in pieces:
        data = b""
        for section in piece.sections:
            file = files[section.file_index]
            file_path = os.path.join(base_path, file.path)
            with open(file_path, "rb") as file:
                file.seek(section.file_offset)
                data += file.read(section.length)
        if len(data) < piece_size:
            data += b"\x00" * (piece_size - len(data))
        piece.base_62_sha1 = base62_sha1_hash_of(data)

def create_live_torrent_from_path(raw_path: str, piece_size: int):
    base_path, files = files_from_path(raw_path)
    torrent_files = list(map(lambda file: TorrentFile(file, os.path.getsize(os.path.join(base_path, file))), files))
    pieces = pack_files_to_pieces(torrent_files, piece_size)
    initiate_piece_hashes(base_path, torrent_files, pieces, piece_size)

    torrent = Torrent(torrent_files, pieces)
    live_torrent = LiveTorrent.from_torrent(base_path, torrent)

    return live_torrent

def send_message(ui_thread_inbox: pyqtSignal, harbor: Harbor, sock: socket, message):
    try:
        message_data = json.dumps(message).encode("utf-8")
        packed_data = struct.pack(">I", len(message_data)) + message_data
        sock.sendall(packed_data)
    except Exception as e:
        print(f"Error sending data to {sock.getpeername()}: {e}")
        ui_thread_inbox.emit(("io_error", f"Error sending data to {sock.getpeername()}: {e}"))
        harbor.socket_receiver_queue_remove_client_command(sock)

class IoThread(QThread):
    ui_thread_inbox_ready = pyqtSignal(object)
    io_thread_inbox: queue.Queue

    def __init__(self, io_thread_inbox: queue.Queue):
        super().__init__()
        self.io_thread_inbox = io_thread_inbox

    def run(self):
        my_peer_id = generate_unique_id()
        print(f"I/O thread: ID is {my_peer_id}")

        my_peer_info = PeerInfo()
        my_peer_info.peer_id = my_peer_id
        my_peer_info.peer_port = PEER_PORT

        executor = ThreadPoolExecutor(max_workers=5)

        peers: dict[socket.socket, PeerInfo] = {}

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((PEER_HOST, PEER_PORT))
        server_socket.listen()
        print(f"I/O thread: listening on {PEER_HOST}:{PEER_PORT} for other peers...")

        harbor = Harbor(server_socket, self.io_thread_inbox)
        harbor.start()

        tracker_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tracker_sock.connect((TARGET_TRACKER_HOST, TARGET_TRACKER_PORT))
        print(f"I/O thread: connected to tracker {TARGET_TRACKER_HOST}:{TARGET_TRACKER_PORT}. Adding to Harbor.")
        harbor.socket_receiver_queue_add_client_command(tracker_sock)

        self.ui_thread_inbox_ready.emit("io_hi")

        stop_requested = False
        keep_running = True
        while keep_running:
            try:
                message = self.io_thread_inbox.get(timeout=0.1)
                message_type = message[0]
                if message_type == "harbor_connection_added":
                    _, sock, peer_name = message
                    if sock == tracker_sock:
                        print(f"I/O thread: connected to tracker {peer_name[0]}:{peer_name[1]}. Sending info.")
                        executor.submit(send_message, self.ui_thread_inbox_ready, harbor, sock, ("peer_info", my_peer_info.to_json()))
                    else:
                        print(f"I/O thread: connected to peer {peer_name[0]}:{peer_name[1]}.")
                elif message_type == "harbor_connection_removed":
                    _, sock, peer_name, caused_by_stop = message
                    if sock == tracker_sock:
                        if caused_by_stop:
                            print(f"I/O thread: disconnected from tracker {peer_name[0]}:{peer_name[1]}.")
                        else:
                            print(f"I/O thread: disconnected from tracker {peer_name[0]}:{peer_name[1]}! Stopping.")
                            stop_requested = True
                elif message_type == "harbor_message":
                    _, sock, peer_name, msg = message
                    if sock == tracker_sock:
                        msg_command_type = msg[0]
                        if msg_command_type == "motd":
                            _, motd = msg
                            print(f"I/O thread: MOTD from tracker {peer_name[0]}:{peer_name[1]}: `{motd}`")
                        else:
                            print(f"I/O thread: message from tracker {peer_name[0]}:{peer_name[1]}: {msg}")
                    else:
                        print(f"I/O thread: message from peer {peer_name[0]}:{peer_name[1]}: {msg}")
                elif message == "harbor_stopped":
                    print(f"I/O thread: Harbor stopped.")
                    keep_running = False

                elif message_type == "ui_create_torrent":
                    _, path, piece_size = message
                    if os.path.exists(path):
                        print(create_live_torrent_from_path(path, piece_size).torrent_json)

                elif message == "ui_quit":
                    stop_requested = True

                else:
                    print(f"I/O thread: I/O message: {message}")
            except queue.Empty:
                continue
            if stop_requested:
                stop_requested = False
                print("I/O thread: stopping Harbor...")
                harbor.stop()

        executor.shutdown()
        print("I/O thread: bye")