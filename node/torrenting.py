import json
from enum import Enum

from hashing import base62_sha1_hash_of
from peer_info import PeerInfo
from torrent_data import TorrentStructure


class PieceState(Enum):
    PENDING_DOWNLOAD = "Pending download"
    PENDING_CHECK = "Pending check"
    COMPLETE = "Complete"


class PersistentTorrentState:
    torrent_hash: str
    torrent_structure: TorrentStructure
    torrent_name: str
    base_path: str
    piece_states: list[PieceState]

    def __init__(self, torrent_hash: str, torrent_structure: TorrentStructure, base_path: str, torrent_name: str,
                 piece_states: list[PieceState]):
        self.torrent_hash = torrent_hash
        self.torrent_structure = torrent_structure
        self.torrent_name = torrent_name
        self.base_path = base_path
        self.piece_states = piece_states

    def __repr__(self):
        return f"LiveTorrent(torrent_hash={self.torrent_hash}, torrent_structure={self.torrent_structure}, base_path={self.base_path}, piece_states={self.piece_states})"

    def to_dict(self):
        data = {
            'torrent_hash': self.torrent_hash,
            'torrent_structure': self.torrent_structure.to_dict(),
            'torrent_name': self.torrent_name,
            'base_path': self.base_path,
            'piece_states': self.piece_states
        }

        return data

    @classmethod
    def from_dict(cls, data: dict):
        torrent_structure = TorrentStructure.from_dict(data['torrent_structure'])
        return cls(
            torrent_hash=data['torrent_hash'],
            torrent_structure=torrent_structure,
            torrent_name=data['torrent_name'],
            base_path=data['base_path'],
            piece_states=data['piece_states']
        )


class EphemeralTorrentState:
    persistent_state: PersistentTorrentState
    torrent_json: str
    last_announced: None

    def __init__(self, s: PersistentTorrentState, torrent_json: str):
        self.persistent_state = s
        self.torrent_json = torrent_json

    @classmethod
    def from_torrent_structure(cls, torrent_structure: TorrentStructure, base_path: str, torrent_name: str,
                               initial_piece_state: PieceState):
        torrent_json = json.dumps(torrent_structure.to_dict())
        torrent_hash = base62_sha1_hash_of(torrent_json.encode("utf-8"))
        piece_states = [initial_piece_state] * len(torrent_structure.pieces)
        persistent_torrent_state = PersistentTorrentState(torrent_hash, torrent_structure, base_path, torrent_name,
                                                          piece_states)
        return cls(persistent_torrent_state, torrent_json)


class EphemeralPeerState:
    peer_name: (str, int)
    peer_info: PeerInfo

    def __init__(self, peer_name: (str, int)):
        self.peer_name = peer_name
        self.peer_info = PeerInfo()
