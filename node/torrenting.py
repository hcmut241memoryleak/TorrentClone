import base64
import json
import socket
import threading

from hashing import base62_sha256_hash_of
from peer_info import PeerInfo
from torrent_data import TorrentStructure


# Serializables


class PersistentTorrentState:
    sha256_hash: str
    torrent_name: str
    base_path: str
    piece_states: list[bool]

    def __init__(self, sha256_hash: str, base_path: str, torrent_name: str,
                 piece_states: list[bool]):
        self.sha256_hash = sha256_hash
        self.torrent_name = torrent_name
        self.base_path = base_path
        self.piece_states = piece_states

    def __repr__(self):
        return f"PersistentTorrentState(sha256_hash={self.sha256_hash}, base_path={self.base_path}, piece_states={self.piece_states})"

    @staticmethod
    def serialize_piece_states(piece_states: list[bool]) -> str:
        return ''.join(str(int(state)) for state in piece_states)

    @staticmethod
    def deserialize_piece_states(compact_str: str) -> list[bool]:
        return [char == "1" for char in compact_str]

    def to_dict(self):
        return {
            'sha256_hash': self.sha256_hash,
            'torrent_name': self.torrent_name,
            'base_path': self.base_path,
            'piece_states': self.serialize_piece_states(self.piece_states)
        }

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            sha256_hash=data['sha256_hash'],
            torrent_name=data['torrent_name'],
            base_path=data['base_path'],
            piece_states=cls.deserialize_piece_states(data['piece_states'])
        )


class PersistentTorrentHashImportState:
    sha256_hash: str
    torrent_name: str
    base_path: str

    def __init__(self, sha256_hash: str, torrent_name: str, base_path: str):
        self.sha256_hash = sha256_hash
        self.torrent_name = torrent_name
        self.base_path = base_path

    def __repr__(self):
        return f"PersistentTorrentHashImportState(sha256_hash={self.sha256_hash}, torrent_name={self.torrent_name}, base_path={self.base_path})"

    def to_dict(self):
        return {
            'sha256_hash': self.sha256_hash,
            'torrent_name': self.torrent_name,
            'base_path': self.base_path
        }

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            sha256_hash=data['sha256_hash'],
            torrent_name=data['torrent_name'],
            base_path=data['base_path']
        )


# States


class EphemeralTorrentState:
    torrent_structure: TorrentStructure
    torrent_json: str
    persistent_state: PersistentTorrentState
    torrent_json_loaded_from_path: str | None
    persistent_state_loaded_from_path: str | None

    def __init__(self, torrent_structure: TorrentStructure, torrent_json: str, persistent_state: PersistentTorrentState,
                 torrent_json_loaded_from_path: str | None, persistent_state_loaded_from_path: str | None):
        self.torrent_structure = torrent_structure
        self.torrent_json = torrent_json
        self.persistent_state = persistent_state
        self.torrent_json_loaded_from_path = torrent_json_loaded_from_path
        self.persistent_state_loaded_from_path = persistent_state_loaded_from_path

    @classmethod
    def from_torrent_structure(cls, torrent_structure: TorrentStructure, base_path: str, torrent_name: str,
                               initial_piece_state: bool):
        torrent_json = json.dumps(torrent_structure.to_dict())
        sha256_hash = base62_sha256_hash_of(torrent_json.encode("utf-8"))
        piece_states = [initial_piece_state] * len(torrent_structure.pieces)
        persistent_torrent_state = PersistentTorrentState(sha256_hash, base_path, torrent_name, piece_states)
        return cls(torrent_structure, torrent_json, persistent_torrent_state, None, None)


class NodeEphemeralPeerState:
    peer_name: (str, int)
    peer_info: PeerInfo
    torrent_states: dict[str, list[bool]]
    send_lock: threading.Lock

    def __init__(self, peer_name: (str, int)):
        self.peer_name = peer_name
        self.peer_info = PeerInfo()
        self.torrent_states = {}
        self.send_lock = threading.Lock()

    @staticmethod
    def serialize_piece_states(piece_states: list[bool]) -> str:
        byte_array = bytearray()
        for i in range(0, len(piece_states), 8):
            chunk = piece_states[i:i + 8]
            byte = sum(1 << (7 - j) for j, bit in enumerate(chunk) if bit)
            byte_array.append(byte)
        b64_encoded = base64.b64encode(byte_array)
        return b64_encoded.decode('utf-8')

    @staticmethod
    def deserialize_piece_states(b64: str) -> list[bool]:
        byte_array = base64.b64decode(b64)
        states = []
        for byte in byte_array:
            for i in range(8):
                states.append(bool((byte >> (7 - i)) & 1))
        return states

    def has_piece(self, sha256_hash: str, piece_index: int):
        if sha256_hash not in self.torrent_states:
            return False
        torrent_state = self.torrent_states[sha256_hash]
        return piece_index < len(torrent_state) and torrent_state[piece_index]


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


class PendingPieceDownload:
    requested_to: socket.socket

    def __init__(self, requested_to: socket.socket):
        self.requested_to = requested_to


class PendingTorrentHashImport:
    requested_to: list[socket.socket]

    def __init__(self, requested_to: list[socket.socket]):
        self.requested_to = requested_to