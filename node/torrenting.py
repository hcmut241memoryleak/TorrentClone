import json
import threading
from enum import Enum

from hashing import base62_sha256_hash_of
from peer_info import PeerInfo
from torrent_data import TorrentStructure


class PieceState(Enum):
    PENDING_DOWNLOAD = 0
    PENDING_CHECK = 1
    COMPLETE = 2


class PersistentTorrentState:
    sha256_hash: str
    torrent_name: str
    base_path: str
    piece_states: list[PieceState]

    def __init__(self, sha256_hash: str, base_path: str, torrent_name: str,
                 piece_states: list[PieceState]):
        self.sha256_hash = sha256_hash
        self.torrent_name = torrent_name
        self.base_path = base_path
        self.piece_states = piece_states

    def __repr__(self):
        return f"PersistentTorrentState(sha256_hash={self.sha256_hash}, base_path={self.base_path}, piece_states={self.piece_states})"

    @staticmethod
    def serialize_piece_states(piece_states: list[PieceState]) -> str:
        return ''.join(str(state.value) for state in piece_states)

    @staticmethod
    def deserialize_piece_states(compact_str: str) -> list[PieceState]:
        def convert_piece_state(value: int) -> PieceState:
            try:
                return PieceState(value)
            except ValueError:
                return PieceState.PENDING_DOWNLOAD
        return [convert_piece_state(int(char)) for char in compact_str]

    def to_dict(self):
        return {
            'sha256_hash': self.sha256_hash,
            'torrent_name': self.torrent_name,
            'base_path': self.base_path,
            'piece_states': ''.join(str(state.value) for state in self.piece_states)
        }

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            sha256_hash=data['sha256_hash'],
            torrent_name=data['torrent_name'],
            base_path=data['base_path'],
            piece_states=cls.deserialize_piece_states(data['piece_states'])
        )


class EphemeralTorrentState:
    torrent_structure: TorrentStructure
    torrent_json: str
    persistent_state: PersistentTorrentState
    last_announced: None

    def __init__(self, t: TorrentStructure, torrent_json: str, s: PersistentTorrentState):
        self.torrent_structure = t
        self.torrent_json = torrent_json
        self.persistent_state = s

    @classmethod
    def from_torrent_structure(cls, torrent_structure: TorrentStructure, base_path: str, torrent_name: str,
                               initial_piece_state: PieceState):
        torrent_json = json.dumps(torrent_structure.to_dict())
        sha256_hash = base62_sha256_hash_of(torrent_json.encode("utf-8"))
        piece_states = [initial_piece_state] * len(torrent_structure.pieces)
        persistent_torrent_state = PersistentTorrentState(sha256_hash, base_path, torrent_name, piece_states)
        return cls(torrent_structure, torrent_json, persistent_torrent_state)


class AnnouncementTorrentState:
    sha256_hash: str
    piece_states: list[PieceState]

    def __init__(self, sha256_hash: str, piece_states: list[PieceState]):
        self.sha256_hash = sha256_hash
        self.piece_states = piece_states

    def __repr__(self):
        return f"AnnouncementTorrentState(sha256_hash={self.sha256_hash}, piece_states={self.piece_states})"

    def to_dict(self):
        return {
            'sha256_hash': self.sha256_hash,
            'piece_states': PersistentTorrentState.serialize_piece_states(self.piece_states)
        }

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            sha256_hash=data['sha256_hash'],
            piece_states=PersistentTorrentState.deserialize_piece_states(data['piece_states'])
        )


class NodeEphemeralPeerState:
    peer_name: (str, int)
    peer_info: PeerInfo
    torrent_states: list[AnnouncementTorrentState]
    send_lock: threading.Lock

    def __init__(self, peer_name: (str, int)):
        self.peer_name = peer_name
        self.peer_info = PeerInfo()
        self.torrent_states = []
        self.send_lock = threading.Lock()


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