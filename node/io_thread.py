import json
import os
import queue
import socket
import struct
from concurrent.futures import ThreadPoolExecutor

from PyQt6.QtCore import QThread, pyqtSignal

from harbor import Harbor
from hashing import base62_sha1_hash_of
from node.torrenting import EphemeralTorrentState, EphemeralPeerState, PieceState
from peer_info import generate_unique_id, PeerInfo
from torrent_data import TorrentFile, pack_files_to_pieces, Piece, TorrentStructure

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
            file_paths.append(os.path.relpath(str(os.path.join(root, file)), base_path))  # TODO: why str()?
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


def create_persistent_torrent_state_from_path(raw_path: str, piece_size: int):
    base_path, files = files_from_path(raw_path)
    torrent_files = list(map(lambda file: TorrentFile(file, os.path.getsize(os.path.join(base_path, file))), files))
    pieces = pack_files_to_pieces(torrent_files, piece_size)
    initiate_piece_hashes(base_path, torrent_files, pieces, piece_size)

    torrent_structure = TorrentStructure(torrent_files, piece_size, pieces)
    torrent_json, persistent_state = EphemeralTorrentState.from_torrent_structure(torrent_structure, base_path,
                                                                                  "torrent", PieceState.COMPLETE)

    return torrent_json, persistent_state


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
    ui_thread_inbox = pyqtSignal(object)
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

        peers: dict[socket.socket, EphemeralPeerState] = {}
        torrent_states: dict[str, EphemeralTorrentState] = {}

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((PEER_HOST, PEER_PORT))
        server_socket.listen()
        print(f"I/O thread: listening on {PEER_HOST}:{PEER_PORT} for other peers...")

        harbor = Harbor(server_socket, self.io_thread_inbox)
        harbor.start()

        tracker_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            tracker_sock.connect((TARGET_TRACKER_HOST, TARGET_TRACKER_PORT))
        except ConnectionRefusedError as e:
            self.ui_thread_inbox.emit(("io_error", f"Error connecting to central tracker: {e}"))
            return
        print(
            f"I/O thread: tracker {TARGET_TRACKER_HOST}:{TARGET_TRACKER_PORT} connected. Adding to Harbor and sending info.")
        harbor.socket_receiver_queue_add_client_command(tracker_sock)
        outgoing_msg = ("peer_info", json.dumps(my_peer_info.to_dict()))
        executor.submit(send_message, self.ui_thread_inbox, harbor, tracker_sock, outgoing_msg)

        self.ui_thread_inbox.emit("io_hi")

        stop_requested = False
        keep_running = True
        while keep_running:
            try:
                message = self.io_thread_inbox.get(timeout=0.1)
                message_type = message[0]

                if message_type == "harbor_connection_added":
                    _, sock, peer_name = message
                    if sock != tracker_sock:
                        peers[sock] = EphemeralPeerState()
                        print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} connected. Sending info.")
                        outgoing_msg = ("peer_info", json.dumps(my_peer_info.to_dict()))
                        executor.submit(send_message, self.ui_thread_inbox, harbor, sock, outgoing_msg)

                elif message_type == "harbor_connection_removed":
                    _, sock, peer_name, caused_by_stop = message
                    if sock == tracker_sock:
                        if caused_by_stop:
                            print(f"I/O thread: tracker {peer_name[0]}:{peer_name[1]} disconnected.")
                        else:
                            print(f"I/O thread: tracker {peer_name[0]}:{peer_name[1]} disconnected! Stopping.")
                            stop_requested = True

                elif message_type == "harbor_message":
                    _, sock, peer_name, msg = message
                    msg_command_type = msg[0]
                    if sock == tracker_sock:
                        if msg_command_type == "motd":
                            _, motd = msg
                            print(f"I/O thread: tracker {peer_name[0]}:{peer_name[1]} sent MOTD: `{motd}`")
                        else:
                            print(f"I/O thread: tracker {peer_name[0]}:{peer_name[1]} sent: {msg}")
                    else:
                        if msg_command_type == "peer_info":
                            _, json_info = msg
                            if sock in peers:
                                info = PeerInfo.from_dict(json.loads(json_info))
                                peers[sock].peer_info = info
                                print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} sent info: {info}")
                        else:
                            print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} sent: {msg}")

                elif message == "harbor_stopped":
                    keep_running = False

                elif message_type == "ui_create_torrent":
                    _, path, piece_size = message
                    if os.path.exists(path):
                        torrent_json, persistent_state = create_persistent_torrent_state_from_path(path, piece_size)
                        torrent_states[persistent_state.torrent_hash] = EphemeralTorrentState(torrent_json,
                                                                                              persistent_state)
                        print(torrent_json)

                elif message == "ui_quit":
                    stop_requested = True

                else:
                    print(f"I/O thread: I/O message: {message}")
            except queue.Empty:
                # TODO: torrent announce
                for peer_socket, peer_info in peers.items():
                    executor.submit(send_message, self.ui_thread_inbox, harbor, peer_socket,
                                    ("greet", "From peer: have a great day!"))

                continue
            if stop_requested:
                stop_requested = False
                harbor.stop()

        executor.shutdown()
