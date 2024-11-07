import json
import os
import queue
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from PyQt6.QtCore import QThread, pyqtSignal

from harbor import Harbor
from hashing import base62_sha1_hash_of, win_filesys_escape_uppercase, win_filesys_unescape_uppercase, \
    base62_sha256_hash_of
from node.torrenting import EphemeralTorrentState, NodeEphemeralPeerState, PieceState, AnnouncementTorrentState, \
    PersistentTorrentState
from peer_info import generate_unique_id, PeerInfo
from torrent_data import TorrentFile, pack_files_to_pieces, Piece, TorrentStructure

TARGET_TRACKER_HOST = '127.0.0.1'
TARGET_TRACKER_PORT = 65432

PEER_HOST = '127.0.0.1'
# PEER_PORT = 65433

TORRENT_STRUCTURE_FILE_SUFFIX = ".torj"
PERSISTENT_TORRENT_STATE_FILE_SUFFIX = ".ptors"


def files_from_path(base_path: str):
    if os.path.isfile(base_path):
        new_base_path = os.path.dirname(base_path)
        return new_base_path, [os.path.relpath(base_path, new_base_path)]

    file_paths = []
    for root, dirs, files in os.walk(base_path):
        for file in files:
            file_paths.append(os.path.relpath(str(os.path.join(root, file)), base_path))  # TODO: why str()?
    return base_path, file_paths


def get_piece_data(base_path: str, files: list[TorrentFile], piece: Piece, piece_size: int):
    data = b""
    for section in piece.sections:
        file = files[section.file_index]
        file_path = os.path.join(base_path, file.path)
        with open(file_path, "rb") as file:
            file.seek(section.file_offset)
            data += file.read(section.length)
    if len(data) < piece_size:
        data += b"\x00" * (piece_size - len(data))
    return data


def initiate_piece_hashes(base_path: str, files: list[TorrentFile], pieces: list[Piece], piece_size: int):
    for piece in pieces:
        piece.base_62_sha1 = base62_sha1_hash_of(get_piece_data(base_path, files, piece, piece_size))


def create_ephemeral_torrent_state_from_path(raw_path: str, torrent_name: str, piece_size: int):
    base_path, files = files_from_path(raw_path)
    torrent_files = [TorrentFile(file, os.path.getsize(os.path.join(base_path, file))) for file in files]

    pieces = pack_files_to_pieces(torrent_files, piece_size)
    initiate_piece_hashes(base_path, torrent_files, pieces, piece_size)

    torrent_structure = TorrentStructure(torrent_files, piece_size, pieces)
    return EphemeralTorrentState.from_torrent_structure(torrent_structure, base_path, torrent_name, PieceState.COMPLETE)


class IoThread(QThread):
    ui_thread_inbox = pyqtSignal(object)
    io_thread_inbox: queue.Queue

    tracker_socket: socket.socket
    tracker_socket_lock: threading.Lock
    peers: dict[socket.socket, NodeEphemeralPeerState]
    torrent_states: dict[str, EphemeralTorrentState]

    harbor: Harbor
    executor: ThreadPoolExecutor

    peer_port: int
    appdata_path: str

    def __init__(self, io_thread_inbox: queue.Queue, port_str: str, appdata_str: str):
        super().__init__()
        self.io_thread_inbox = io_thread_inbox
        self.tracker_socket_lock = threading.Lock()
        self.peers = {}
        self.torrent_states = {}
        self.peer_port = int(port_str)
        self.appdata_path = os.path.join(os.getcwd(), appdata_str)
        print(self.appdata_path)

    def load_torrent_states_from_disk(self):
        folder = os.path.join(self.appdata_path, "torrents")
        if not os.path.isdir(folder):
            return
        for file in os.listdir(folder):
            if file.endswith(PERSISTENT_TORRENT_STATE_FILE_SUFFIX):
                apparent_escaped_sha256_hash = file[:-len(PERSISTENT_TORRENT_STATE_FILE_SUFFIX)]

                torrent_structure_file = os.path.join(folder, f"{apparent_escaped_sha256_hash}{TORRENT_STRUCTURE_FILE_SUFFIX}")
                if not os.path.isfile(torrent_structure_file):
                    print(f"I/O thread: accompanying torrent structure file for {file} not found. Skipping.")
                    continue

                apparent_unescaped_sha256_hash = win_filesys_unescape_uppercase(apparent_escaped_sha256_hash)

                try:
                    with open(os.path.join(folder, file), "rb") as bin_file:
                        persistent_data = bin_file.read()
                    persistent_state = PersistentTorrentState.from_dict(json.loads(persistent_data.decode("utf-8")))
                except Exception as e:
                    print(f"I/O thread: could not load persistent torrent state file {file}: {e}. Skipping.")
                    continue

                try:
                    with open(os.path.join(folder, torrent_structure_file), "rb") as bin_file:
                        structure_data = bin_file.read()
                    true_hash = base62_sha256_hash_of(structure_data)
                    if true_hash != apparent_unescaped_sha256_hash:
                        print(f"I/O thread: SHA256 hash of torrent structure file {e} doesn't match its own filename. Skipping.")
                        continue
                    structure_json = structure_data.decode("utf-8")
                    structure = TorrentStructure.from_dict(json.loads(structure_json))
                except Exception as e:
                    print(f"I/O thread: could not load torrent structure file {file}: {e}. Skipping.")
                    continue

                self.torrent_states[true_hash] = EphemeralTorrentState(structure, structure_json, persistent_state)
        # for sha256_hash, ephemeral_state in self.torrent_states.items():
        #     filepath = os.path.join(self.appdata_path, f"torrents/{win_filesys_escape_uppercase(sha256_hash)}.ptors")
        #     json_dump = json.dumps(ephemeral_state.persistent_state.to_dict())
        #     with open(filepath, "wt") as file:
        #         file.write(json_dump)

    def save_torrent_states_to_disk(self):
        if not os.path.exists(self.appdata_path):
            os.mkdir(self.appdata_path)
        for sha256_hash, ephemeral_state in self.torrent_states.items():
            escaped_hash = win_filesys_escape_uppercase(sha256_hash)

            state_filepath = os.path.join(self.appdata_path, f"torrents/{escaped_hash}{PERSISTENT_TORRENT_STATE_FILE_SUFFIX}")
            state_json_dump = json.dumps(ephemeral_state.persistent_state.to_dict()).encode("utf-8")
            try:
                with open(state_filepath, "wb") as file:
                    file.write(state_json_dump)
            except Exception as e:
                print(f"I/O thread: could not write file {state_filepath}: {e}. Data loss.")
                continue

            structure_filepath = os.path.join(self.appdata_path, f"torrents/{escaped_hash}{TORRENT_STRUCTURE_FILE_SUFFIX}")
            structure_json = ephemeral_state.torrent_json.encode("utf-8")
            try:
                with open(structure_filepath, "wb") as file:
                    file.write(structure_json)
            except Exception as e:
                print(f"I/O thread: could not write file {structure_filepath}: {e}. Data loss.")
                continue

    def send_bytes(self, sock: socket.socket, socket_lock: threading.Lock, b: bytes):
        peer_name = "(broken socket)"
        try:
            peer_name = sock.getpeername()
            with socket_lock:
                sock.sendall(b)
        except Exception as e:
            error_string = f"Error sending data to {peer_name}: {e}"
            print(error_string)
            self.ui_thread_inbox.emit(("io_error", error_string))
            self.harbor.socket_receiver_queue_remove_client_command(sock)

    def send_message(self, sock: socket.socket, socket_lock: threading.Lock, tag: str, data: bytes):
        tag_bytes = tag.encode("utf-8")
        packed_data = struct.pack(">II", len(tag_bytes), len(data)) + tag_bytes + data
        self.send_bytes(sock, socket_lock, packed_data)

    def send_json_message(self, sock: socket.socket, socket_lock: threading.Lock, tag: str, message):
        try:
            json_data = json.dumps(message).encode("utf-8")
            self.send_message(sock, socket_lock, tag, json_data)
        except Exception as e:
            error_string = f"Error serializing message `{message}`: {e}"
            print(error_string)
            self.ui_thread_inbox.emit(("io_error", error_string))
            return

    def mass_send_json_message(self, socks: list[tuple[socket.socket, threading.Lock]], tag: str, message):
        try:
            json_data = json.dumps(message).encode("utf-8")
            tag_bytes = tag.encode("utf-8")
            packed_data = struct.pack(">II", len(tag_bytes) + len(json_data)) + tag_bytes + json_data
        except Exception as e:
            error_string = f"Error serializing message `{message}`: {e}"
            print(error_string)
            self.ui_thread_inbox.emit(("io_error", error_string))
            return

        for sock, socket_lock in socks:
            self.executor.submit(self.send_bytes, sock, socket_lock, packed_data)

    def ui_update_peers_view(self):
        self.ui_thread_inbox.emit(("io_peers_changed", self.peers))

    def ui_update_torrents_view(self):
        self.ui_thread_inbox.emit(("io_torrents_changed", self.torrent_states))

    def announce_torrents_to_tracker(self):
        tracker_announcement_message = [
            torrent_state.persistent_state.sha256_hash for torrent_state in self.torrent_states.values()
        ]
        self.executor.submit(self.send_json_message, self.tracker_socket, self.tracker_socket_lock, "peer_torrent_list", tracker_announcement_message)

    def announce_torrents_to_peers(self):
        if len(self.torrent_states) != 0:
            node_announcement_message = [
                AnnouncementTorrentState(
                    sha256_hash=torrent_state.persistent_state.sha256_hash,
                    piece_states=[state == PieceState.COMPLETE for state in torrent_state.persistent_state.piece_states]
                ).to_dict() for torrent_state in self.torrent_states.values()
            ]
            socks = [(sock, state.send_lock) for sock, state in self.peers.items()]
            self.executor.submit(self.mass_send_json_message, socks, "peer_torrent_announcement", node_announcement_message)

    def send_piece_to_peer(self, ephemeral_torrent_state: EphemeralTorrentState, piece_index: int, peer_sock: socket.socket, peer_socket_lock: threading.Lock):
        if piece_index < len(ephemeral_torrent_state.persistent_state.piece_states) and ephemeral_torrent_state.persistent_state.piece_states[piece_index] == PieceState.COMPLETE:
            base_path = ephemeral_torrent_state.persistent_state.base_path
            files = ephemeral_torrent_state.torrent_structure.files
            piece = ephemeral_torrent_state.torrent_structure.pieces[piece_index]
            piece_size = ephemeral_torrent_state.torrent_structure.piece_size
            piece_data = get_piece_data(base_path, files, piece, piece_size)

            outgoing_msg = struct.pack(">II", len(ephemeral_torrent_state.persistent_state.sha256_hash), piece_index)
            outgoing_msg += ephemeral_torrent_state.persistent_state.sha256_hash.encode("utf-8")
            outgoing_msg += piece_data

            self.send_message(peer_sock, peer_socket_lock, "peer_piece_contents", outgoing_msg)

    def merge_piece(self, ephemeral_torrent_state: EphemeralTorrentState, piece_index: int, piece_data: bytes):

        pass

    def on_peer_info(self, sock: socket.socket, peer_name: tuple[str, int], msg: bytes):
        if sock in self.peers:
            try:
                info = PeerInfo.from_dict(json.loads(msg.decode("utf-8")))
                self.peers[sock].peer_info = info
                print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} sent info: {info}")
                self.ui_update_peers_view()
            except Exception as e:
                pass

    def on_peer_torrent_announcement(self, sock: socket.socket, peer_name: tuple[str, int], msg: bytes):
        try:
            torrent_states = [AnnouncementTorrentState.from_dict(d) for d in json.loads(msg.decode("utf-8"))]
            self.peers[sock].torrent_states = torrent_states
            print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} announced: {len(torrent_states)} torrents")
            self.ui_update_peers_view()
        except Exception as e:
            pass

    def on_peer_piece_contents(self, sock: socket.socket, peer_name: tuple[str, int], msg: bytes):
        try:
            preamble_length = 8
            if len(msg) < preamble_length:
                return

            sha256_hash_bytes_len, piece_index = struct.unpack(">II", msg[:preamble_length])
            if len(msg) - preamble_length < sha256_hash_bytes_len:
                return

            sha256_hash_bytes = msg[preamble_length:preamble_length+sha256_hash_bytes_len]
            sha256_hash = sha256_hash_bytes.decode("utf-8")


            if sha256_hash not in self.torrent_states:
                return

            torrent_state = self.torrent_states[sha256_hash]
            piece_size = torrent_state.torrent_structure.piece_size

            if piece_index >= len(torrent_state.torrent_structure.pieces):
                return
            if torrent_state.persistent_state.piece_states[piece_index] != PieceState.PENDING_DOWNLOAD:
                return

            if len(msg) - 8 - sha256_hash_bytes_len != piece_size:
                return

            piece_data = msg[8+sha256_hash_bytes_len:]
            apparent_sha1_piece_hash = base62_sha1_hash_of(piece_data)
            known_sha1_piece_hash = torrent_state.torrent_structure.pieces[piece_index].base_62_sha1
            if apparent_sha1_piece_hash != known_sha1_piece_hash:
                return

            self.merge_piece(torrent_state, piece_index, piece_data)

        except Exception as e:
            pass

    def on_harbor_message(self, sock: socket.socket, peer_name: tuple[str, int], tag: str, msg: bytes):
        if sock == self.tracker_socket:
            if tag == "motd":
                motd = json.loads(msg.decode("utf-8"))
                print(f"I/O thread: tracker {peer_name[0]}:{peer_name[1]} sent MOTD: `{motd}`")
            else:
                print(f"I/O thread: tracker {peer_name[0]}:{peer_name[1]} sent unknown message `{tag}` with {len(msg)} bytes")
        else:
            if tag == "peer_info":
                self.on_peer_info(sock, peer_name, msg)
            elif tag == "peer_torrent_announcement":
                self.on_peer_torrent_announcement(sock, peer_name, msg)
            elif tag == "peer_piece_contents":
                self.on_peer_piece_contents(sock, peer_name, msg)
            else:
                print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} sent: {msg}")

    def run(self):
        self.load_torrent_states_from_disk()

        my_peer_id = generate_unique_id()
        print(f"I/O thread: ID is {my_peer_id}")

        my_peer_info = PeerInfo()
        my_peer_info.peer_id = my_peer_id
        my_peer_info.peer_port = self.peer_port

        self.executor = ThreadPoolExecutor(max_workers=16)

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((PEER_HOST, self.peer_port))
        server_socket.listen()
        print(f"I/O thread: listening on {PEER_HOST}:{self.peer_port} for other peers...")

        self.harbor = Harbor(server_socket, self.io_thread_inbox)
        self.harbor.start()

        self.tracker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.tracker_socket.connect((TARGET_TRACKER_HOST, TARGET_TRACKER_PORT))
        except Exception as e:
            self.ui_thread_inbox.emit(("io_error", f"Error connecting to central tracker: {e}"))
            return
        print(
            f"I/O thread: tracker {TARGET_TRACKER_HOST}:{TARGET_TRACKER_PORT} connected. Adding to Harbor and sending info.")
        self.harbor.socket_receiver_queue_add_client_command(self.tracker_socket)
        self.executor.submit(self.send_json_message, self.tracker_socket, self.tracker_socket_lock, "peer_info", my_peer_info.to_dict())

        self.ui_thread_inbox.emit("io_hi")

        if len(self.torrent_states) > 0:
            self.ui_update_torrents_view()
            self.announce_torrents_to_tracker()

        last_reannounced_torrents_to_tracker = time.time()
        last_reannounced_torrents_to_peers = time.time()

        stop_requested = False
        keep_running = True
        while keep_running:
            try:
                message = self.io_thread_inbox.get(timeout=0.1)
                message_type = message[0]

                if message_type == "harbor_connection_added":
                    _, sock, peer_name = message
                    if sock != self.tracker_socket:
                        self.peers[sock] = NodeEphemeralPeerState(peer_name)
                        print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} connected. Sending info.")
                        outgoing_msg = my_peer_info.to_dict()
                        self.executor.submit(self.send_json_message, sock, self.peers[sock].send_lock, "peer_info", outgoing_msg)

                        self.ui_update_peers_view()

                elif message_type == "harbor_connection_removed":
                    _, sock, peer_name, caused_by_stop = message
                    if sock == self.tracker_socket:
                        if caused_by_stop:
                            print(f"I/O thread: tracker {peer_name[0]}:{peer_name[1]} disconnected.")
                        else:
                            print(f"I/O thread: tracker {peer_name[0]}:{peer_name[1]} disconnected! Stopping.")
                            self.ui_thread_inbox.emit(("io_error", f"Lost connection to tracker {peer_name[0]}:{peer_name[1]}! I/O thread is stopping."))
                            stop_requested = True
                    else:
                        del self.peers[sock]
                        self.ui_update_peers_view()

                elif message_type == "harbor_message":
                    _, sock, peer_name, tag, msg = message
                    self.on_harbor_message(sock, peer_name, tag, msg)

                elif message == "harbor_stopped":
                    keep_running = False

                elif message_type == "ui_create_torrent":
                    _, path, torrent_name, piece_size = message
                    if os.path.exists(path):
                        ephemeral_state = create_ephemeral_torrent_state_from_path(path, torrent_name, piece_size)
                        self.torrent_states[ephemeral_state.persistent_state.sha256_hash] = ephemeral_state
                        self.announce_torrents_to_tracker()
                        self.announce_torrents_to_peers()
                        self.ui_update_torrents_view()
                    else:
                        self.ui_thread_inbox.emit(("io_error", f"Error trying to create torrent: path `{path}` doesn't exist"))

                elif message == "ui_quit":
                    stop_requested = True
                else:
                    print(f"I/O thread: I/O message: {message}")
            except queue.Empty:
                pass

            current_time = time.time()
            if current_time - last_reannounced_torrents_to_peers >= 2: # reannounce every 2 seconds
                last_reannounced_torrents_to_peers = current_time
                self.announce_torrents_to_peers()
            # Reannouncements to tracker is currently disabled! I will only reannounce when torrents are added/removed.
            # It is up to the peers to individually announce to each other about their torrent progresses (i.e. piece states).
            # if current_time - last_reannounced_torrents_to_tracker >= 10: # reannounce every 10 seconds
            #     last_reannounced_torrents_to_tracker = current_time
            #     self.announce_torrents_to_tracker()

            if stop_requested:
                stop_requested = False
                self.harbor.stop()

        self.executor.shutdown()
        self.save_torrent_states_to_disk()
