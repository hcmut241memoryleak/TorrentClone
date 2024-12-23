import json
import os
import platform
import queue
import socket
import struct
import subprocess
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

from PyQt6.QtCore import QThread, pyqtSignal, QUrl
from PyQt6.QtGui import QDesktopServices

from harbor import Harbor
from hashing import base62_sha1_hash_of, win_filesys_escape_uppercase, win_filesys_unescape_uppercase, \
    base62_sha256_hash_of
from node.torrenting import EphemeralTorrentState, NodeEphemeralPeerState, PersistentTorrentState, PendingPieceDownload, \
    PersistentTorrentHashImportState, PendingTorrentHashImport, PeerToPeerTorrentAnnouncement
from node.ui_messages import UiTorrentState, UiTorrentHashImportState
from peer_info import generate_unique_id, PeerInfo
from torrent_data import TorrentFile, Piece, TorrentStructure, PieceSection

TARGET_TRACKER_PORT = 65432

PEER_HOST = '0.0.0.0'
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


def pack_files_to_pieces(files: list[TorrentFile], piece_size):
    pieces = []
    current_piece = Piece()
    current_piece_position = 0

    for file_index, file in enumerate(files):
        current_file_position = 0
        while current_file_position < file.byte_count:
            if (file.byte_count - current_file_position) >= (piece_size - current_piece_position):  # need a new piece
                current_piece.sections.append(
                    PieceSection(piece_size - current_piece_position, file_index, current_file_position))
                current_file_position += piece_size - current_piece_position
                pieces.append(current_piece)
                current_piece = Piece()
                current_piece_position = 0
            else:
                current_piece.sections.append(
                    PieceSection(file.byte_count - current_file_position, file_index, current_file_position))
                current_piece_position += file.byte_count - current_file_position
                current_file_position = file.byte_count

    if len(current_piece.sections) > 0:
        pieces.append(current_piece)

    return pieces


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


def create_ephemeral_torrent_state_from_torrent_json(torrent_json: str, sha256_hash: str, save_path: str, torrent_name: str):
    torrent_structure = TorrentStructure.from_dict(json.loads(torrent_json))

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


def merge_piece(base_path: str, files: list[TorrentFile], piece: Piece, piece_data: bytes):
    current_piece_offset = 0
    for section in piece.sections:
        torrent_file = files[section.file_index]
        file_path = os.path.join(base_path, torrent_file.path)
        if os.path.exists(file_path) and not os.path.isfile(file_path):
            return # ?????
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        if not os.path.exists(file_path):
            with open(file_path, "w+b") as file:
                target_length = torrent_file.byte_count
                file.seek(target_length - 1)
                file.write(b'\0')
        with open(file_path, "r+b") as file:
            section_data = piece_data[current_piece_offset:(current_piece_offset + section.length)]
            file.seek(section.file_offset)
            file.write(section_data)
        current_piece_offset += section.length


class IoThread(QThread):
    ui_thread_inbox = pyqtSignal(object)
    io_thread_inbox: queue.Queue

    tracker_socket: socket.socket
    tracker_socket_lock: threading.Lock
    peers: dict[socket.socket, NodeEphemeralPeerState]

    torrent_states: dict[str, EphemeralTorrentState]
    torrent_hash_import_states: dict[str, PersistentTorrentHashImportState]

    harbor: Harbor
    executor: ThreadPoolExecutor

    pending_piece_downloads: dict[tuple[EphemeralTorrentState, int], PendingPieceDownload]
    pending_torrent_hash_imports: dict[str, PendingTorrentHashImport]

    peer_port: int
    appdata_path: str

    target_tracker_host: str

    def __init__(self, io_thread_inbox: queue.Queue, port_str: str, appdata_str: str, target_tracker_host: str):
        super().__init__()
        self.io_thread_inbox = io_thread_inbox

        self.tracker_socket_lock = threading.Lock()
        self.peers = {}
        self.torrent_hash_import_states = {}

        self.torrent_states = {}

        self.pending_piece_downloads = {}
        self.pending_torrent_hash_imports = {}

        self.peer_port = int(port_str)
        self.appdata_path = os.path.join(os.getcwd(), appdata_str)

        self.target_tracker_host = target_tracker_host

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
            self.harbor.socket_receiver_queue_add_client_command(peer_socket)
        except Exception as e:
            traceback.print_exc()
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
        ui_torrent_hash_import_states = [
            UiTorrentHashImportState(
                sha256_hash,
                persistent_import_state.torrent_name,
                sha256_hash in self.pending_torrent_hash_imports
            ) for sha256_hash, persistent_import_state in self.torrent_hash_import_states.items()
        ]
        ui_torrent_states = [
            UiTorrentState(
                sha256_hash,
                ephemeral_torrent_state.persistent_state.torrent_name,
                ephemeral_torrent_state.persistent_state.piece_states.copy(), # copy because it's sent across a thread
                sum(state == ephemeral_torrent_state for state, piece_index in self.pending_piece_downloads)
            ) for sha256_hash, ephemeral_torrent_state in self.torrent_states.items()
        ]
        self.ui_thread_inbox.emit(("io_torrents_changed", ui_torrent_hash_import_states, ui_torrent_states))

    def announce_torrents_to_tracker(self):
        tracker_announcement_message = [
            torrent_state.persistent_state.sha256_hash for torrent_state in self.torrent_states.values()
        ] + [
            import_state.sha256_hash for import_state in self.torrent_hash_import_states.values()
        ]
        self.executor.submit(self.send_json_message, self.tracker_socket, self.tracker_socket_lock, "peer_torrent_list",
                             tracker_announcement_message)

    def announce_torrents_to_peer(self, sock: socket.socket, socket_lock: threading.Lock):
        node_announcement_message = PeerToPeerTorrentAnnouncement(
            list(self.torrent_hash_import_states.keys()),
            {torrent_state.persistent_state.sha256_hash: torrent_state.persistent_state.piece_states for torrent_state in self.torrent_states.values()}
        ).to_dict()
        self.executor.submit(self.send_json_message, sock, socket_lock, "peer_torrent_announcement", node_announcement_message)

    def announce_torrents_to_all_peers(self):
        node_announcement_message = PeerToPeerTorrentAnnouncement(
            list(self.torrent_hash_import_states.keys()),
            {torrent_state.persistent_state.sha256_hash: torrent_state.persistent_state.piece_states for torrent_state in self.torrent_states.values()}
        ).to_dict()
        socks = [(sock, state.send_lock) for sock, state in self.peers.items()]
        self.executor.submit(self.mass_send_json_message, socks, "peer_torrent_announcement", node_announcement_message)

    def maintain_request_lists(self):
        # Process piece requests

        pending_piece_list_limit = 128
        per_peer_piece_request_limit = 32

        per_peer_piece_request_count: dict[socket.socket, int] = {}

        torrent_piece_pairs_to_delete: list[tuple[EphemeralTorrentState, int]] = []
        for torrent_piece_pair, pending_piece_download in self.pending_piece_downloads.items():
            req_sock = pending_piece_download.requested_to
            if req_sock not in self.peers:
                torrent_piece_pairs_to_delete.append(torrent_piece_pair)
            else:
                if req_sock in per_peer_piece_request_count:
                    per_peer_piece_request_count[req_sock] = per_peer_piece_request_count[req_sock] + 1
                else:
                    per_peer_piece_request_count[req_sock] = 1
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
                        if sock in per_peer_piece_request_count and per_peer_piece_request_count[sock] > per_peer_piece_request_limit:
                            continue
                        if peer_state.has_piece(torrent_sha256_hash, piece_index):
                            if sock in per_peer_piece_request_count:
                                per_peer_piece_request_count[sock] = per_peer_piece_request_count[sock] + 1
                            else:
                                per_peer_piece_request_count[sock] = 1
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

                        if pending_piece.requested_to not in self.peers:
                            if target_sock is None:
                                # it ain't downloadable anymore, begone.
                                del self.pending_piece_downloads[torrent_state, piece_index]
                            else:
                                pending_piece.requested_to = target_sock
                                self.request_piece_from_peer(target_sock, self.peers[target_sock].send_lock, torrent_sha256_hash, piece_index)

        # Process torrent JSON requests

        torrent_hash_imports_to_delete: list[str] = []
        for torrent_hash, pending_torrent_hash_import in self.pending_torrent_hash_imports.items():
            pending_torrent_hash_import.requested_to = [sock for sock in pending_torrent_hash_import.requested_to if sock in self.peers]
            if len(pending_torrent_hash_import.requested_to) == 0:
                torrent_hash_imports_to_delete.append(torrent_hash)
        for torrent_hash_import_to_delete in torrent_hash_imports_to_delete:
            del self.pending_torrent_hash_imports[torrent_hash_import_to_delete]

        for torrent_hash, persistent_torrent_hash_import in self.torrent_hash_import_states.items():
            # now is the time to check if the torrent json is actually downloadable: there needs to one or more people who have it
            target_socks: list[socket.socket] = []
            for sock, peer_state in self.peers.items():
                if torrent_hash in peer_state.last_announcement.torrent_states:
                    target_socks.append(sock)

            if torrent_hash not in self.pending_torrent_hash_imports:
                if len(target_socks) > 0:
                    # it's downloadable but it's not downloaded yet
                    pending_import = PendingTorrentHashImport(target_socks)
                    self.pending_torrent_hash_imports[torrent_hash] = pending_import
                    self.request_torrent_json_from_peers([(sock, self.peers[sock].send_lock) for sock in target_socks], torrent_hash)
            else:
                pending_import = self.pending_torrent_hash_imports[torrent_hash]
                new_socks = [sock for sock in target_socks if sock not in pending_import.requested_to]
                if len(target_socks) == 0:
                    # it ain't downloadable anymore, begone.
                    del self.pending_torrent_hash_imports[torrent_hash]
                else:
                    if len(new_socks) > 0:
                        self.request_torrent_json_from_peers([(sock, self.peers[sock].send_lock) for sock in new_socks], torrent_hash)
                    pending_import.requested_to = target_socks

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

            if base62_sha1_hash_of(piece_data) != ephemeral_torrent_state.torrent_structure.pieces[piece_index].base_62_sha1:
                print(f"send_piece_to_peer: `{ephemeral_torrent_state.persistent_state.torrent_name}`#{piece_index} hash not lining up, corrupted file?")
                print(f"                    from file: {base62_sha1_hash_of(piece_data)}")
                print(f"                    from torrent structure: {ephemeral_torrent_state.torrent_structure.pieces[piece_index].base_62_sha1}")
                return

            outgoing_msg = struct.pack(">II", len(ephemeral_torrent_state.persistent_state.sha256_hash), piece_index)
            outgoing_msg += ephemeral_torrent_state.persistent_state.sha256_hash.encode("utf-8")
            outgoing_msg += piece_data

            self.executor.submit(self.send_message, peer_sock, peer_socket_lock, "peer_piece_contents", outgoing_msg)

    def request_torrent_json_from_peers(self, peer_socks: list[tuple[socket.socket, threading.Lock]], torrent_sha256_hash: str):
        outgoing_msg = torrent_sha256_hash
        self.executor.submit(self.mass_send_json_message, peer_socks, "peer_request_torrent_json", outgoing_msg)

    def send_torrent_json_to_peer(self, sha256_hash: str, torrent_json: str, peer_sock: socket.socket, peer_socket_lock: threading.Lock):
        outgoing_msg = struct.pack(">I", len(sha256_hash))
        outgoing_msg += sha256_hash.encode("utf-8")
        outgoing_msg += torrent_json.encode("utf-8")

        self.executor.submit(self.send_message, peer_sock, peer_socket_lock, "peer_torrent_json", outgoing_msg)

    def on_peer_info(self, sock: socket.socket, peer_name: tuple[str, int], msg: bytes):
        if sock in self.peers:
            try:
                info = PeerInfo.from_dict(json.loads(msg.decode("utf-8")))
                self.peers[sock].peer_info = info
                print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} sent info: {info}")

                for peer_sock, peer_state in self.peers.items():
                    if peer_sock != sock and peer_state.peer_info.peer_id == info.peer_id:
                        print(f"I/O thread: Removing duplicate connection by ID to peer {peer_name[0]}:{peer_name[1]}.")
                        self.harbor.socket_receiver_queue_remove_client_command(sock)

                self.ui_update_peers_view()
            except Exception as e:
                traceback.print_exc()
                pass

    def on_peer_torrent_announcement(self, sock: socket.socket, peer_name: tuple[str, int], msg: bytes):
        try:
            announcement = PeerToPeerTorrentAnnouncement.from_dict(json.loads(msg.decode("utf-8")))
            my_hashes = list(self.torrent_hash_import_states.keys()) + list(self.torrent_states.keys())
            their_hashes = announcement.hash_import_states + list(announcement.torrent_states.keys())
            has_any_hashes_in_common = any(h in my_hashes for h in their_hashes)
            if not has_any_hashes_in_common:
                # Kick peer for not having any torrents in common
                self.harbor.socket_receiver_queue_remove_client_command(sock)
            else:
                self.peers[sock].last_announcement = announcement
                self.maintain_request_lists()
                self.ui_update_peers_view()
        except Exception as e:
            traceback.print_exc()
            pass

    def on_peer_request_piece(self, sock: socket.socket, peer_name: tuple[str, int], msg: bytes):
        if sock in self.peers:
            try:
                sha256_hash, piece_index = json.loads(msg.decode("utf-8"))
                if sha256_hash in self.torrent_states:
                    torrent_state = self.torrent_states[sha256_hash]
                    self.send_piece_to_peer(torrent_state, piece_index, sock, self.peers[sock].send_lock)
            except Exception as e:
                traceback.print_exc()
                pass

    def on_peer_piece_contents(self, sock: socket.socket, peer_name: tuple[str, int], msg: bytes):
        try:
            preamble_length = 8
            if len(msg) < preamble_length:
                print("peer piece contents msg: msg shorter than preamble length")
                return

            sha256_hash_bytes_len, piece_index = struct.unpack(">II", msg[:preamble_length])
            if len(msg) - preamble_length < sha256_hash_bytes_len:
                print("peer piece contents msg: sha256 hash section shorter than expected")
                return

            sha256_hash_bytes = msg[preamble_length:preamble_length + sha256_hash_bytes_len]
            sha256_hash = sha256_hash_bytes.decode("utf-8")

            if sha256_hash not in self.torrent_states:
                print("peer piece contents msg: sha256 hash not here")
                return

            torrent_state = self.torrent_states[sha256_hash]
            piece_size = torrent_state.torrent_structure.piece_size

            if piece_index >= len(torrent_state.torrent_structure.pieces):
                print("peer piece contents msg: piece index out of range")
                return
            piece = torrent_state.torrent_structure.pieces[piece_index]

            if torrent_state.persistent_state.piece_states[piece_index]:  # already completed this piece
                print("peer piece contents msg: piece is already completed")
                return

            if len(msg) - preamble_length - sha256_hash_bytes_len != piece_size:
                print("peer piece contents msg: piece contents section shorter than expected")
                return

            piece_data = msg[preamble_length + sha256_hash_bytes_len:]
            apparent_sha1_piece_hash = base62_sha1_hash_of(piece_data)
            known_sha1_piece_hash = piece.base_62_sha1
            if apparent_sha1_piece_hash != known_sha1_piece_hash:
                print("peer piece contents msg: sha1 hash not lining up")
                return

            if (torrent_state, piece_index) in self.pending_piece_downloads:
                del self.pending_piece_downloads[torrent_state, piece_index]
            merge_piece(torrent_state.persistent_state.base_path, torrent_state.torrent_structure.files, piece, piece_data)
            torrent_state.persistent_state.piece_states[piece_index] = True # completed
            self.maintain_request_lists()
            # self.announce_torrents_to_all_peers() # of course, if we announced for every piece it would spam
            self.ui_update_torrents_view()

        except Exception as e:
            traceback.print_exc()
            pass

    def on_peer_request_torrent_json(self, sock: socket.socket, peer_name: tuple[str, int], msg: bytes):
        if sock in self.peers:
            try:
                sha256_hash = json.loads(msg.decode("utf-8"))
                if sha256_hash in self.torrent_states:
                    torrent_state = self.torrent_states[sha256_hash]
                    self.send_torrent_json_to_peer(torrent_state.persistent_state.sha256_hash, torrent_state.torrent_json, sock, self.peers[sock].send_lock)
            except Exception as e:
                traceback.print_exc()
                pass

    def on_peer_torrent_json(self, sock: socket.socket, peer_name: tuple[str, int], msg: bytes):
        try:
            preamble_length = 4
            if len(msg) < preamble_length:
                return

            sha256_hash_bytes_len = struct.unpack(">I", msg[:preamble_length])[0]
            if len(msg) - preamble_length < sha256_hash_bytes_len:
                return

            sha256_hash_bytes = msg[preamble_length:preamble_length + sha256_hash_bytes_len]
            sha256_hash = sha256_hash_bytes.decode("utf-8")

            if sha256_hash not in self.torrent_hash_import_states:
                return

            apparent_torrent_json_bytes = msg[preamble_length + sha256_hash_bytes_len:]
            apparent_sha256_hash = base62_sha256_hash_of(apparent_torrent_json_bytes)
            if apparent_sha256_hash != sha256_hash:
                return

            if sha256_hash in self.pending_torrent_hash_imports:
                del self.pending_torrent_hash_imports[sha256_hash]

            import_state = self.torrent_hash_import_states[sha256_hash]
            del self.torrent_hash_import_states[sha256_hash]

            if not os.path.exists(import_state.base_path) or not os.path.isdir(import_state.base_path) or not os.path.isabs(import_state.base_path):
                error_string = f"Error trying to import torrent by hash: path `{import_state.base_path}` can't be used"
                self.ui_thread_inbox.emit(("io_error", error_string))
                return

            ephemeral_state = create_ephemeral_torrent_state_from_torrent_json(apparent_torrent_json_bytes.decode("utf-8"), sha256_hash, import_state.base_path, import_state.torrent_name)

            # This should literally never happen but who knows.
            if ephemeral_state.persistent_state.sha256_hash in self.torrent_states:
                error_string = f"Error trying to import torrent by hash: torrent of hash {sha256_hash} is already imported"
                self.ui_thread_inbox.emit(("io_error", error_string))
                return

            self.torrent_states[ephemeral_state.persistent_state.sha256_hash] = ephemeral_state
            self.announce_torrents_to_tracker()
            self.announce_torrents_to_all_peers()
            self.maintain_request_lists()
            self.ui_update_torrents_view()

        except Exception as e:
            traceback.print_exc()
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
            elif tag == "peer_request_torrent_json":
                self.on_peer_request_torrent_json(sock, peer_name, msg)
            elif tag == "peer_torrent_json":
                self.on_peer_torrent_json(sock, peer_name, msg)
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

        print((self.target_tracker_host, TARGET_TRACKER_PORT))

        self.tracker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.tracker_socket.connect((self.target_tracker_host, TARGET_TRACKER_PORT))
        except Exception as e:
            self.ui_thread_inbox.emit(("io_error", f"Error connecting to central tracker: {e}"))
            return
        print(
            f"I/O thread: tracker {self.target_tracker_host}:{TARGET_TRACKER_PORT} connected. Adding to Harbor and sending info.")
        self.harbor.socket_receiver_queue_add_client_command(self.tracker_socket)
        self.executor.submit(self.send_json_message, self.tracker_socket, self.tracker_socket_lock, "peer_info",
                             my_peer_info.to_dict())

        self.ui_thread_inbox.emit("io_hi")

        if len(self.torrent_states) > 0:
            self.announce_torrents_to_tracker()
            self.maintain_request_lists()
            self.ui_update_torrents_view()

        last_reannounced_torrents_to_tracker = time.time()
        last_reannounced_torrents_to_peers = time.time()

        stop_requested = False
        keep_running = True
        while keep_running:
            try:
                message = self.io_thread_inbox.get(timeout=1)
                message_type = message[0]

                if message_type == "harbor_connection_added":
                    _, sock, peer_name = message
                    if sock != self.tracker_socket:
                        self.peers[sock] = NodeEphemeralPeerState(peer_name)
                        print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} connected. Sending info and torrent states.")
                        outgoing_msg = my_peer_info.to_dict()
                        self.executor.submit(self.send_json_message, sock, self.peers[sock].send_lock, "peer_info",
                                             outgoing_msg)
                        self.announce_torrents_to_peer(sock, self.peers[sock].send_lock)

                        self.ui_update_peers_view()
                elif message_type == "harbor_connection_removed":
                    _, sock, peer_name, caused_by_stop = message
                    if sock == self.tracker_socket:
                        if caused_by_stop:
                            print(f"I/O thread: tracker {peer_name[0]}:{peer_name[1]} disconnected.")
                        else:
                            print(f"I/O thread: tracker {peer_name[0]}:{peer_name[1]} disconnected! Stopping.")
                            error_string = f"Tracker {peer_name[0]}:{peer_name[1]} disconnected! I/O thread stopping."
                            self.ui_thread_inbox.emit(("io_error", error_string))
                            stop_requested = True
                    else:
                        print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} disconnected.")
                        del self.peers[sock]
                        self.maintain_request_lists()
                        self.ui_update_peers_view()
                elif message_type == "harbor_message":
                    _, sock, peer_name, tag, msg = message
                    self.on_harbor_message(sock, peer_name, tag, msg)
                elif message == "harbor_stopped":
                    keep_running = False

                elif message_type == "ui_create_torrent":
                    _, path, torrent_name, piece_size = message
                    if os.path.exists(path) or not os.path.isabs(path):
                        ephemeral_state = create_ephemeral_torrent_state_from_path(path, torrent_name, piece_size)
                        self.torrent_states[ephemeral_state.persistent_state.sha256_hash] = ephemeral_state
                        self.maintain_request_lists()  # not necessary because there's nothing to download
                        self.announce_torrents_to_tracker()
                        self.announce_torrents_to_all_peers()
                        self.ui_update_torrents_view()
                    else:
                        error_string = f"Error creating torrent: path `{path}` doesn't exist or isn't an absolute path"
                        self.ui_thread_inbox.emit(("io_error", error_string))
                elif message_type == "ui_import_torrent":
                    _, torrent_file_path, save_path, torrent_name = message
                    # TODO: check if torrent_file_path is under appdata/torrents,
                    #  just in case it was imported from within there,
                    #  probably not necessary cuz already deduped below
                    if os.path.isfile(torrent_file_path):
                        if not os.path.exists(save_path) or not os.path.isdir(save_path) or not os.path.isabs(save_path):
                            error_string = f"Error creating torrent: path `{path}` doesn't exist or isn't an absolute path"
                            self.ui_thread_inbox.emit(("io_error", error_string))
                        else:
                            ephemeral_state = create_ephemeral_torrent_state_from_torrent_structure_file(torrent_file_path,
                                                                                                         save_path,
                                                                                                         torrent_name)
                            sha256_hash = ephemeral_state.persistent_state.sha256_hash
                            if sha256_hash in self.torrent_states:
                                error_string = f"Error importing torrent: torrent of hash {sha256_hash} is already imported"
                                self.ui_thread_inbox.emit(("io_error", error_string))
                                return

                            self.torrent_states[ephemeral_state.persistent_state.sha256_hash] = ephemeral_state
                            self.announce_torrents_to_tracker()
                            self.announce_torrents_to_all_peers()
                            self.maintain_request_lists()
                            self.ui_update_torrents_view()
                    else:
                        self.ui_thread_inbox.emit(
                            ("io_error", f"Error trying to import torrent: path `{torrent_file_path}` is not a file"))
                elif message_type == "ui_open_torrent_location":
                    _, torrent_hash = message
                    if torrent_hash in self.torrent_states:
                        torrent_state = self.torrent_states[torrent_hash]
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
                                traceback.print_exc()
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
                                traceback.print_exc()
                                pass
                        if ephemeral_state.persistent_state_loaded_from_path is not None:
                            try:
                                os.remove(ephemeral_state.persistent_state_loaded_from_path)
                            except Exception as e:
                                traceback.print_exc()
                                pass

                        self.announce_torrents_to_tracker()
                        self.announce_torrents_to_all_peers()
                        self.maintain_request_lists()
                        self.ui_update_torrents_view()
                elif message_type == "ui_import_torrent_by_hash":
                    _, torrent_hash, name, base_path = message
                    if torrent_hash in self.torrent_hash_import_states or torrent_hash in self.torrent_states:
                        error_string = f"Error trying to import torrent hash: Hash {torrent_hash} is already added"
                        self.ui_thread_inbox.emit(("io_error", error_string))
                    elif not os.path.exists(base_path) or not os.path.isabs(base_path):
                        error_string = f"Error trying to import torrent hash: Path {base_path} does not exist or is not absolute"
                        self.ui_thread_inbox.emit(("io_error", error_string))
                    else:
                        self.torrent_hash_import_states[torrent_hash] = PersistentTorrentHashImportState(torrent_hash, name, base_path)

                        self.announce_torrents_to_tracker()
                        self.announce_torrents_to_all_peers()
                        self.maintain_request_lists()
                        self.ui_update_torrents_view()

                elif message == "ui_quit":
                    stop_requested = True

                else:
                    print(f"I/O thread: I/O message: {message}")
            except queue.Empty:
                pass

            current_time = time.time()
            if current_time - last_reannounced_torrents_to_peers >= 5:  # reannounce every 5 seconds
                last_reannounced_torrents_to_peers = current_time
                if len(self.peers) > 0:
                    self.announce_torrents_to_all_peers()
            if current_time - last_reannounced_torrents_to_tracker >= 10:  # reannounce every 10 seconds
                last_reannounced_torrents_to_tracker = current_time
                self.announce_torrents_to_tracker()

            if stop_requested:
                stop_requested = False
                self.harbor.stop()

        self.executor.shutdown()
        self.save_torrent_states_to_disk()
