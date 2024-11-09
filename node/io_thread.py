import json
import os
import platform
import queue
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from PyQt6.QtCore import QThread, pyqtSignal, QUrl
from PyQt6.QtGui import QDesktopServices

from harbor import Harbor
from hashing import base62_sha1_hash_of, win_filesys_escape_uppercase, win_filesys_unescape_uppercase, \
    base62_sha256_hash_of
from node.torrenting import EphemeralTorrentState, NodeEphemeralPeerState, PersistentTorrentState, PendingPieceDownload
from peer_info import generate_unique_id, PeerInfo
from torrent_data import TorrentFile, pack_files_to_pieces, Piece, TorrentStructure

TARGET_TRACKER_HOST = '127.0.0.1'
TARGET_TRACKER_PORT = 65432

PEER_HOST = '127.0.0.1'
# PEER_PORT = 65433

TORRENT_STRUCTURE_FILE_SUFFIX = ".torj"
PERSISTENT_TORRENT_STATE_FILE_SUFFIX = ".ptors"


def highlight_path_in_explorer(directory_path: str):
    if not os.path.exists(directory_path):
        return

    def open_in_explorer():
        if platform.system() == "Windows":
            subprocess.Popen(f'explorer /select,"{os.path.abspath(directory_path)}"', shell=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            QDesktopServices.openUrl(QUrl.fromLocalFile(directory_path))

    threading.Thread(target=open_in_explorer, daemon=True).start()


def find_common_base(paths):
    directories = [os.path.dirname(path) for path in paths]
    base = directories[0]
    for dir_path in directories[1:]:
        while not dir_path.startswith(base):
            base = os.path.dirname(base)
    return base


def files_from_path(raw_path: str):
    base_path = os.path.dirname(raw_path)
    file_or_folder_name = os.path.relpath(raw_path, base_path)
    if os.path.isfile(raw_path):
        return base_path, [file_or_folder_name]

    file_paths = []
    for root, dirs, files in os.walk(raw_path):
        for file in files:
            # Notice how I'm using base_path instead of raw_path in the relpath call here.
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
    return EphemeralTorrentState.from_torrent_structure(torrent_structure, base_path, torrent_name, True)


def create_ephemeral_torrent_state_from_torrent_structure_file(path: str, save_path: str, torrent_name: str):
    with open(path, "rb") as file:
        torrent_json_bytes = file.read()
        torrent_json = torrent_json_bytes.decode("utf-8")
        torrent_structure = TorrentStructure.from_dict(json.loads(torrent_json))

    sha256_hash = base62_sha256_hash_of(torrent_json_bytes)

    if torrent_name == "":
        if len(torrent_structure.files) == 1:
            torrent_name = os.path.basename(torrent_structure.files[0].path)
        else:
            torrent_name = os.path.basename(find_common_base([file.path for file in torrent_structure.files]))
    if torrent_name == "":
        torrent_name = f"(hash {sha256_hash})"

    piece_states = [False] * len(torrent_structure.pieces)
    persistent_state = PersistentTorrentState(sha256_hash, save_path, torrent_name, piece_states)
    return EphemeralTorrentState(torrent_structure, torrent_json, persistent_state, None, None)


class IoThread(QThread):
    ui_thread_inbox = pyqtSignal(object)
    io_thread_inbox: queue.Queue

    tracker_socket: socket.socket
    tracker_socket_lock: threading.Lock
    peers: dict[socket.socket, NodeEphemeralPeerState]
    torrent_states: dict[str, EphemeralTorrentState]

    harbor: Harbor
    executor: ThreadPoolExecutor

    pending_piece_downloads: dict[tuple[EphemeralTorrentState, int], PendingPieceDownload]

    peer_port: int
    appdata_path: str

    def __init__(self, io_thread_inbox: queue.Queue, port_str: str, appdata_str: str):
        super().__init__()
        self.io_thread_inbox = io_thread_inbox
        self.tracker_socket_lock = threading.Lock()

        self.peers = {}
        self.torrent_states = {}

        self.pending_piece_downloads = {}

        self.peer_port = int(port_str)
        self.appdata_path = os.path.join(os.getcwd(), appdata_str)

    def load_torrent_states_from_disk(self):
        folder = os.path.join(self.appdata_path, "torrents")
        if not os.path.isdir(folder):
            return
        for file in os.listdir(folder):
            if file.endswith(PERSISTENT_TORRENT_STATE_FILE_SUFFIX):
                apparent_escaped_sha256_hash = file[:-len(PERSISTENT_TORRENT_STATE_FILE_SUFFIX)]

                torrent_structure_file_path = os.path.join(folder,
                                                           f"{apparent_escaped_sha256_hash}{TORRENT_STRUCTURE_FILE_SUFFIX}")
                if not os.path.isfile(torrent_structure_file_path):
                    print(f"I/O thread: accompanying torrent structure file for {file} not found. Skipping.")
                    continue

                apparent_unescaped_sha256_hash = win_filesys_unescape_uppercase(apparent_escaped_sha256_hash)

                full_file_path = os.path.join(folder, file)
                try:
                    with open(full_file_path, "rb") as bin_file:
                        persistent_data = bin_file.read()
                    persistent_state = PersistentTorrentState.from_dict(json.loads(persistent_data.decode("utf-8")))
                except Exception as e:
                    print(f"I/O thread: could not load persistent torrent state file {file}: {e}. Skipping.")
                    continue

                try:
                    with open(torrent_structure_file_path, "rb") as bin_file:
                        structure_data = bin_file.read()
                    true_hash = base62_sha256_hash_of(structure_data)
                    if true_hash != apparent_unescaped_sha256_hash:
                        print(
                            f"I/O thread: SHA256 hash of torrent structure file {file} doesn't match its own filename. Skipping.")
                        continue
                    structure_json = structure_data.decode("utf-8")
                    structure = TorrentStructure.from_dict(json.loads(structure_json))
                except Exception as e:
                    print(f"I/O thread: could not load torrent structure file {file}: {e}. Skipping.")
                    continue

                self.torrent_states[true_hash] = EphemeralTorrentState(structure, structure_json, persistent_state,
                                                                       torrent_structure_file_path, full_file_path)

    def save_torrent_states_to_disk(self):
        for sha256_hash, ephemeral_state in self.torrent_states.items():
            escaped_hash = win_filesys_escape_uppercase(sha256_hash)

            state_filepath = os.path.join(self.appdata_path,
                                          f"torrents/{escaped_hash}{PERSISTENT_TORRENT_STATE_FILE_SUFFIX}")
            state_json_dump = json.dumps(ephemeral_state.persistent_state.to_dict()).encode("utf-8")
            try:
                os.makedirs(os.path.dirname(state_filepath), exist_ok=True)
                with open(state_filepath, "wb") as file:
                    file.write(state_json_dump)
            except Exception as e:
                print(f"I/O thread: could not write file {state_filepath}: {e}. Data loss.")
                continue

            structure_filepath = os.path.join(self.appdata_path,
                                              f"torrents/{escaped_hash}{TORRENT_STRUCTURE_FILE_SUFFIX}")
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

    def connect_to_peer(self, target_host: str, target_port: int):
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((target_host, target_port))
            self.io_thread_inbox.put(("self_peer_socket_connected", peer_socket))
        except Exception as e:
            pass

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
            packed_data = struct.pack(">II", len(tag_bytes), len(json_data)) + tag_bytes + json_data
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
        self.ui_thread_inbox.emit(("io_torrents_changed", [], self.torrent_states))

    def announce_torrents_to_tracker(self):
        tracker_announcement_message = [
            torrent_state.persistent_state.sha256_hash for torrent_state in self.torrent_states.values()
        ]
        self.executor.submit(self.send_json_message, self.tracker_socket, self.tracker_socket_lock, "peer_torrent_list",
                             tracker_announcement_message)

    def announce_torrents_to_peers(self):
        if len(self.torrent_states) != 0:
            node_announcement_message = {}
            for torrent_state in self.torrent_states.values():
                node_announcement_message[
                    torrent_state.persistent_state.sha256_hash] = NodeEphemeralPeerState.serialize_piece_states(
                    torrent_state.persistent_state.piece_states)
            socks = [(sock, state.send_lock) for sock, state in self.peers.items()]
            self.executor.submit(self.mass_send_json_message, socks, "peer_torrent_announcement",
                                 node_announcement_message)

    def process_pending_pieces(self):
        pending_piece_list_limit = 16
        per_peer_request_limit = 16

        per_peer_request_count: dict[socket.socket, int] = {}

        torrent_piece_pairs_to_delete: list[tuple[EphemeralTorrentState, int]] = []
        for torrent_piece_pair, pending_piece_download in self.pending_piece_downloads.items():
            req_sock = pending_piece_download.requested_to
            if req_sock not in self.peers:
                torrent_piece_pairs_to_delete.append(torrent_piece_pair)
            else:
                if req_sock in per_peer_request_count:
                    per_peer_request_count[req_sock] = per_peer_request_count[req_sock] + 1
                else:
                    per_peer_request_count[req_sock] = 1
        for torrent_piece_pair_to_delete in torrent_piece_pairs_to_delete:
            del self.pending_piece_downloads[torrent_piece_pair_to_delete]

        for torrent_sha256_hash, torrent_state in self.torrent_states.items():
            if len(self.pending_piece_downloads) >= pending_piece_list_limit:
                break
            for piece_index in range(len(torrent_state.torrent_structure.pieces)):
                if len(self.pending_piece_downloads) >= pending_piece_list_limit:
                    break
                if not torrent_state.persistent_state.piece_states[piece_index]:  # piece not downloaded
                    # now is the time to check if the piece is actually downloadable: there needs to be someone who has the piece
                    target_sock: socket.socket | None = None
                    for sock, peer_state in self.peers.items():
                        if sock in per_peer_request_count and per_peer_request_count[sock] > per_peer_request_limit:
                            continue
                        if peer_state.has_piece(torrent_sha256_hash, piece_index):
                            if sock in per_peer_request_count:
                                per_peer_request_count[sock] = per_peer_request_count[sock] + 1
                            else:
                                per_peer_request_count[sock] = 1
                            target_sock = sock
                            break

                    if (torrent_state, piece_index) not in self.pending_piece_downloads:
                        if target_sock is not None:
                            # it's downloadable but it's not downloaded yet
                            pending_piece = PendingPieceDownload(target_sock)
                            self.pending_piece_downloads[torrent_state, piece_index] = pending_piece

                            self.request_piece_from_peer(target_sock, self.peers[target_sock].send_lock,
                                                         torrent_sha256_hash, piece_index)
                    else:
                        pending_piece = self.pending_piece_downloads[torrent_state, piece_index]
                        if target_sock is None:
                            # it ain't downloadable anymore, begone.
                            del self.pending_piece_downloads[torrent_state, piece_index]
                        elif pending_piece.requested_to not in self.peers:
                            pending_piece.requested_to = target_sock

                            self.request_piece_from_peer(target_sock, self.peers[target_sock].send_lock,
                                                         torrent_sha256_hash, piece_index)

    def request_piece_from_peer(self, peer_sock: socket.socket, peer_socket_lock: threading.Lock,
                                torrent_sha256_hash: str, piece_index: int):
        outgoing_msg = (torrent_sha256_hash, piece_index)
        self.executor.submit(self.send_json_message, peer_sock, peer_socket_lock, "peer_request_piece", outgoing_msg)

    def send_piece_to_peer(self, ephemeral_torrent_state: EphemeralTorrentState, piece_index: int,
                           peer_sock: socket.socket, peer_socket_lock: threading.Lock):
        if piece_index < len(ephemeral_torrent_state.persistent_state.piece_states) and \
                ephemeral_torrent_state.persistent_state.piece_states[piece_index]:
            base_path = ephemeral_torrent_state.persistent_state.base_path
            files = ephemeral_torrent_state.torrent_structure.files
            piece = ephemeral_torrent_state.torrent_structure.pieces[piece_index]
            piece_size = ephemeral_torrent_state.torrent_structure.piece_size
            piece_data = get_piece_data(base_path, files, piece, piece_size)

            outgoing_msg = struct.pack(">II", len(ephemeral_torrent_state.persistent_state.sha256_hash), piece_index)
            outgoing_msg += ephemeral_torrent_state.persistent_state.sha256_hash.encode("utf-8")
            outgoing_msg += piece_data

            self.executor.submit(self.send_message, peer_sock, peer_socket_lock, "peer_piece_contents", outgoing_msg)

    def merge_piece(self, ephemeral_torrent_state: EphemeralTorrentState, piece_index: int, piece_data: bytes):
        piece = ephemeral_torrent_state.torrent_structure.pieces[piece_index]
        current_piece_offset = 0
        for section in piece.sections:
            torrent_file = ephemeral_torrent_state.torrent_structure.files[section.file_index]
            file_path = os.path.join(ephemeral_torrent_state.persistent_state.base_path, torrent_file.path)
            if os.path.exists(file_path) and not os.path.isfile(file_path):
                return  # ?????
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "wb+") as file:
                file.seek(section.file_offset)
                file.write(piece_data[current_piece_offset:current_piece_offset + section.length])

                current_size = file.tell()
                target_length = torrent_file.byte_count
                if current_size < target_length:
                    file.seek(target_length - 1)
                    file.write(b'\0')
            current_piece_offset += section.length

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
            torrent_states = json.loads(msg.decode("utf-8"))
            if not isinstance(torrent_states, dict):
                return
            deserialized: dict[str, list[bool]] = {}
            has_any_hashes_in_common = False
            for sha256_hash, serialized_piece_states in torrent_states.items():
                if not isinstance(sha256_hash, str) or not isinstance(serialized_piece_states, str):
                    return
                if sha256_hash in self.torrent_states:
                    has_any_hashes_in_common = True
                deserialized[sha256_hash] = NodeEphemeralPeerState.deserialize_piece_states(serialized_piece_states)

            if not has_any_hashes_in_common:
                # Kick peer for not having any torrents in common
                self.harbor.socket_receiver_queue_remove_client_command(sock)
            else:
                self.peers[sock].torrent_states = torrent_states
                self.process_pending_pieces()
                self.ui_update_peers_view()
        except Exception as e:
            pass

    def on_peer_request_piece(self, sock: socket.socket, peer_name: tuple[str, int], msg: bytes):
        if sock in self.peers:
            try:
                sha256_hash, piece_index = json.loads(msg.decode("utf-8"))
                if sha256_hash in self.torrent_states:
                    torrent_state = self.torrent_states[sha256_hash]
                    self.send_piece_to_peer(torrent_state, piece_index, sock, self.peers[sock].send_lock)
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

            sha256_hash_bytes = msg[preamble_length:preamble_length + sha256_hash_bytes_len]
            sha256_hash = sha256_hash_bytes.decode("utf-8")

            if sha256_hash not in self.torrent_states:
                return

            torrent_state = self.torrent_states[sha256_hash]
            piece_size = torrent_state.torrent_structure.piece_size

            if piece_index >= len(torrent_state.torrent_structure.pieces):
                return
            if torrent_state.persistent_state.piece_states[piece_index]:  # already completed this piece
                return

            if len(msg) - 8 - sha256_hash_bytes_len != piece_size:
                return

            piece_data = msg[8 + sha256_hash_bytes_len:]
            apparent_sha1_piece_hash = base62_sha1_hash_of(piece_data)
            known_sha1_piece_hash = torrent_state.torrent_structure.pieces[piece_index].base_62_sha1
            if apparent_sha1_piece_hash != known_sha1_piece_hash:
                return

            if (torrent_state, piece_index) in self.pending_piece_downloads:
                del self.pending_piece_downloads[torrent_state, piece_index]
            self.merge_piece(torrent_state, piece_index, piece_data)
            torrent_state.persistent_state.piece_states[piece_index] = True  # completed
            self.process_pending_pieces()
            self.ui_update_torrents_view()

        except Exception as e:
            pass

    def on_harbor_message(self, sock: socket.socket, peer_name: tuple[str, int], tag: str, msg: bytes):
        if sock == self.tracker_socket:
            if tag == "motd":
                motd = json.loads(msg.decode("utf-8"))
                print(f"I/O thread: tracker {peer_name[0]}:{peer_name[1]} sent MOTD: `{motd}`")
            elif tag == "peers":
                peer_list = json.loads(msg.decode("utf-8"))
                for peer_id, peer_host, peer_port in peer_list:
                    if not any(peer_id == p.peer_info.peer_id for p in self.peers.values()):
                        self.executor.submit(self.connect_to_peer, peer_host, peer_port)
            else:
                print(
                    f"I/O thread: tracker {peer_name[0]}:{peer_name[1]} sent unknown message `{tag}` with {len(msg)} bytes")
        else:
            if tag == "peer_info":
                self.on_peer_info(sock, peer_name, msg)
            elif tag == "peer_torrent_announcement":
                self.on_peer_torrent_announcement(sock, peer_name, msg)
            elif tag == "peer_request_piece":
                self.on_peer_request_piece(sock, peer_name, msg)
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
        self.executor.submit(self.send_json_message, self.tracker_socket, self.tracker_socket_lock, "peer_info",
                             my_peer_info.to_dict())

        self.ui_thread_inbox.emit("io_hi")

        if len(self.torrent_states) > 0:
            self.process_pending_pieces()
            self.ui_update_torrents_view()
            self.announce_torrents_to_tracker()

        last_reannounced_torrents_to_tracker = time.time()
        last_reannounced_torrents_to_peers = time.time()

        stop_requested = False
        keep_running = True
        while keep_running:
            try:
                message = self.io_thread_inbox.get(timeout=1)
                message_type = message[0]

                if message_type == "self_peer_socket_connected":
                    _, sock = message
                    self.harbor.socket_receiver_queue_add_client_command(sock)

                elif message_type == "harbor_connection_added":
                    _, sock, peer_name = message
                    if sock != self.tracker_socket:
                        self.peers[sock] = NodeEphemeralPeerState(peer_name)
                        print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} connected. Sending info.")
                        outgoing_msg = my_peer_info.to_dict()
                        self.executor.submit(self.send_json_message, sock, self.peers[sock].send_lock, "peer_info",
                                             outgoing_msg)

                        self.ui_update_peers_view()
                elif message_type == "harbor_connection_removed":
                    _, sock, peer_name, caused_by_stop = message
                    if sock == self.tracker_socket:
                        if caused_by_stop:
                            print(f"I/O thread: tracker {peer_name[0]}:{peer_name[1]} disconnected.")
                        else:
                            print(f"I/O thread: tracker {peer_name[0]}:{peer_name[1]} disconnected! Stopping.")
                            self.ui_thread_inbox.emit(("io_error",
                                                       f"Lost connection to tracker {peer_name[0]}:{peer_name[1]}! I/O thread is stopping."))
                            stop_requested = True
                    else:
                        del self.peers[sock]
                        self.process_pending_pieces()
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
                        self.process_pending_pieces()  # not necessary because there's nothing to download but whatever, habit
                        self.announce_torrents_to_tracker()
                        self.announce_torrents_to_peers()
                        self.ui_update_torrents_view()
                    else:
                        self.ui_thread_inbox.emit(
                            ("io_error", f"Error trying to create torrent: path `{path}` doesn't exist"))
                elif message_type == "ui_import_torrent":
                    _, torrent_file_path, save_path, torrent_name = message
                    # TODO: check if torrent_file_path is under appdata/torrents just in case the user is an idiot and imports from within there
                    if os.path.isfile(torrent_file_path):
                        ephemeral_state = create_ephemeral_torrent_state_from_torrent_structure_file(torrent_file_path,
                                                                                                     save_path,
                                                                                                     torrent_name)

                        if ephemeral_state.persistent_state.sha256_hash in self.torrent_states:
                            self.ui_thread_inbox.emit(("io_error",
                                                       f"Error trying to import torrent: torrent of hash {ephemeral_state.persistent_state.sha256_hash} is already imported"))
                            return

                        self.torrent_states[ephemeral_state.persistent_state.sha256_hash] = ephemeral_state
                        self.announce_torrents_to_tracker()
                        self.announce_torrents_to_peers()
                        self.process_pending_pieces()
                        self.ui_update_torrents_view()
                    else:
                        self.ui_thread_inbox.emit(
                            ("io_error", f"Error trying to import torrent: path `{torrent_file_path}` is not a file"))
                elif message_type == "ui_open_torrent_location":
                    _, torrent_hash = message
                    if torrent_hash in self.torrent_states:
                        torrent_state = self.torrent_states[torrent_hash]
                        path_to_highlight = ""
                        if len(torrent_state.torrent_structure.files) == 1:
                            path_to_highlight = os.path.join(torrent_state.persistent_state.base_path,
                                                             torrent_state.torrent_structure.files[0].path)
                        else:
                            path_to_highlight = find_common_base(
                                [file.path for file in torrent_state.torrent_structure.files])
                            if path_to_highlight == "":
                                path_to_highlight = torrent_state.persistent_state.base_path
                            else:
                                path_to_highlight = os.path.join(torrent_state.persistent_state.base_path,
                                                                 path_to_highlight)
                        highlight_path_in_explorer(path_to_highlight)
                elif message_type == "ui_export_torrent":
                    _, torrent_hash, output_path = message
                    if torrent_hash in self.torrent_states:
                        if os.path.isabs(output_path):
                            torrent_json_encoded = self.torrent_states[torrent_hash].torrent_json.encode("utf-8")
                            try:
                                with open(output_path, "wb") as file:
                                    file.write(torrent_json_encoded)
                                highlight_path_in_explorer(output_path)
                            except Exception as e:
                                pass
                        else:
                            self.ui_thread_inbox.emit(
                                ("io_error", f"Error trying to export torrent: path `{output_path}` is not absolute"))
                elif message_type == "ui_rename_torrent":
                    _, torrent_hash, new_name = message
                    if torrent_hash in self.torrent_states:
                        self.torrent_states[torrent_hash].persistent_state.torrent_name = new_name
                        self.ui_update_torrents_view()
                elif message_type == "ui_remove_torrent":
                    _, torrent_hash = message
                    if torrent_hash in self.torrent_states:
                        ephemeral_state = self.torrent_states[torrent_hash]

                        del self.torrent_states[torrent_hash]
                        torrent_piece_pairs_to_delete: list[tuple[EphemeralTorrentState, int]] = []
                        for torrent_piece_pair, pending_piece_download in self.pending_piece_downloads.items():
                            if torrent_piece_pair[0] == ephemeral_state:
                                torrent_piece_pairs_to_delete.append(torrent_piece_pair)
                        for torrent_piece_pair_to_delete in torrent_piece_pairs_to_delete:
                            del self.pending_piece_downloads[torrent_piece_pair_to_delete]

                        if ephemeral_state.torrent_json_loaded_from_path is not None:
                            try:
                                os.remove(ephemeral_state.torrent_json_loaded_from_path)
                            except Exception as e:
                                pass
                        if ephemeral_state.persistent_state_loaded_from_path is not None:
                            try:
                                os.remove(ephemeral_state.persistent_state_loaded_from_path)
                            except Exception as e:
                                pass

                        self.announce_torrents_to_tracker()
                        self.announce_torrents_to_peers()
                        self.process_pending_pieces()
                        self.ui_update_torrents_view()
                elif message == "ui_quit":
                    stop_requested = True

                else:
                    print(f"I/O thread: I/O message: {message}")
            except queue.Empty:
                pass

            current_time = time.time()
            if current_time - last_reannounced_torrents_to_peers >= 5:  # reannounce every 2 seconds
                last_reannounced_torrents_to_peers = current_time
                if len(self.torrent_states) > 0:
                    self.announce_torrents_to_peers()
            if current_time - last_reannounced_torrents_to_tracker >= 10:  # reannounce every 10 seconds
                last_reannounced_torrents_to_tracker = current_time
                if len(self.torrent_states) > 0:
                    self.announce_torrents_to_tracker()

            if stop_requested:
                stop_requested = False
                self.harbor.stop()

        self.executor.shutdown()
        self.save_torrent_states_to_disk()
