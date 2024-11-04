import json
import os
import queue
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor

from PyQt6.QtCore import QThread, pyqtSignal

from harbor import Harbor
from hashing import base62_sha1_hash_of
from node.torrenting import EphemeralTorrentState, NodeEphemeralPeerState, PieceState, AnnouncementTorrentState
from peer_info import generate_unique_id, PeerInfo
from torrent_data import TorrentFile, pack_files_to_pieces, Piece, TorrentStructure

TARGET_TRACKER_HOST = '127.0.0.1'
TARGET_TRACKER_PORT = 65432

PEER_HOST = '127.0.0.1'
PEER_PORT = 65433


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
    peers: dict[socket.socket, NodeEphemeralPeerState]
    torrent_states: dict[str, EphemeralTorrentState]

    harbor: Harbor
    executor: ThreadPoolExecutor

    def __init__(self, io_thread_inbox: queue.Queue):
        super().__init__()
        self.io_thread_inbox = io_thread_inbox
        self.peers = {}
        self.torrent_states = {}

    def send_message(self, sock: socket, message):
        try:
            message_data = json.dumps(message).encode("utf-8")
            packed_data = struct.pack(">I", len(message_data)) + message_data
        except Exception as e:
            err_string = f"Error serializing message `{message}`: {e}"
            print(err_string)
            self.ui_thread_inbox.emit(("io_error", err_string))
            return

        try:
            sock.sendall(packed_data)
        except Exception as e:
            print(f"Error sending data to {sock.getpeername()}: {e}")
            self.ui_thread_inbox.emit(("io_error", f"Error sending data to {sock.getpeername()}: {e}"))
            self.harbor.socket_receiver_queue_remove_client_command(sock)


    def mass_send_message(self, socks: list[socket], message):
        try:
            message_data = json.dumps(message).encode("utf-8")
            packed_data = struct.pack(">I", len(message_data)) + message_data
        except Exception as e:
            err_string = f"Error serializing message `{message}`: {e}"
            print(err_string)
            self.ui_thread_inbox.emit(("io_error", err_string))
            return

        for sock in socks:
            try:
                sock.sendall(packed_data)
            except Exception as e:
                print(f"Error sending data to {sock.getpeername()}: {e}")
                self.ui_thread_inbox.emit(("io_error", f"Error sending data to {sock.getpeername()}: {e}"))
                self.harbor.socket_receiver_queue_remove_client_command(sock)

    def ui_update_peers_view(self):
        self.ui_thread_inbox.emit(("io_peers_changed", self.peers))

    def ui_update_torrents_view(self):
        self.ui_thread_inbox.emit(("io_torrents_changed", self.torrent_states))

    def announce_torrents_to_tracker(self):
        tracker_announcement_message = ("peer_torrent_list", [
            torrent_state.persistent_state.sha256_hash for torrent_state in self.torrent_states.values()
        ])
        self.executor.submit(self.send_message, self.tracker_socket, tracker_announcement_message)

    def announce_torrents_to_peers(self):
        if len(self.torrent_states) != 0:
            node_announcement_message = ("peer_torrent_announcement", [
                AnnouncementTorrentState(
                    sha256_hash=torrent_state.persistent_state.sha256_hash,
                    piece_states=torrent_state.persistent_state.piece_states
                ).to_dict() for torrent_state in self.torrent_states.values()
            ])
            self.executor.submit(self.mass_send_message, list(self.peers.keys()), node_announcement_message)

    def run(self):
        my_peer_id = generate_unique_id()
        print(f"I/O thread: ID is {my_peer_id}")

        my_peer_info = PeerInfo()
        my_peer_info.peer_id = my_peer_id
        my_peer_info.peer_port = PEER_PORT

        self.executor = ThreadPoolExecutor(max_workers=5)

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((PEER_HOST, PEER_PORT))
        server_socket.listen()
        print(f"I/O thread: listening on {PEER_HOST}:{PEER_PORT} for other peers...")

        self.harbor = Harbor(server_socket, self.io_thread_inbox)
        self.harbor.start()

        self.tracker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.tracker_socket.connect((TARGET_TRACKER_HOST, TARGET_TRACKER_PORT))
        except ConnectionRefusedError as e:
            self.ui_thread_inbox.emit(("io_error", f"Error connecting to central tracker: {e}"))
            return
        print(
            f"I/O thread: tracker {TARGET_TRACKER_HOST}:{TARGET_TRACKER_PORT} connected. Adding to Harbor and sending info.")
        self.harbor.socket_receiver_queue_add_client_command(self.tracker_socket)
        self.executor.submit(self.send_message, self.tracker_socket, ("peer_info", my_peer_info.to_dict()))

        self.ui_thread_inbox.emit("io_hi")

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
                        outgoing_msg = ("peer_info", my_peer_info.to_dict())
                        self.executor.submit(self.send_message, sock, outgoing_msg)

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
                    _, sock, peer_name, msg = message
                    msg_command_type = msg[0]
                    if sock == self.tracker_socket:
                        if msg_command_type == "motd":
                            _, motd = msg
                            print(f"I/O thread: tracker {peer_name[0]}:{peer_name[1]} sent MOTD: `{motd}`")
                        else:
                            print(f"I/O thread: tracker {peer_name[0]}:{peer_name[1]} sent: {msg}")
                    else:
                        if msg_command_type == "peer_info":
                            _, dict_info = msg
                            if sock in self.peers:
                                info = PeerInfo.from_dict(dict_info)
                                self.peers[sock].peer_info = info
                                print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} sent info: {info}")
                                self.ui_update_peers_view()
                        elif msg_command_type == "peer_torrent_announcement":
                            _, dicts_torrent_states = msg
                            if sock in self.peers:
                                torrent_states = [AnnouncementTorrentState.from_dict(d) for d in dicts_torrent_states]
                                self.peers[sock].torrent_states = torrent_states
                                print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} announced: {len(torrent_states)} torrents")
                                self.ui_update_peers_view()
                        else:
                            print(f"I/O thread: peer {peer_name[0]}:{peer_name[1]} sent: {msg}")

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
            # Reannouncements to tracker is currently disabled! I will only reannouce when torrents are added/removed.
            # It is up to the peers to individually announce to each other about their torrent progresses (i.e. piece states).
            # if current_time - last_reannounced_torrents_to_tracker >= 10: # reannounce every 10 seconds
            #     last_reannounced_torrents_to_tracker = current_time
            #     self.announce_torrents_to_tracker()

            if stop_requested:
                stop_requested = False
                self.harbor.stop()

        self.executor.shutdown()
