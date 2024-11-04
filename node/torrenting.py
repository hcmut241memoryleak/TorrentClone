import json

from hashing import base62_sha1_hash_of
from peer_info import PeerInfo
from torrent_data import TorrentStructure, TorrentFile

class PersistentTorrentState:
    torrent_hash: str
    torrent_structure: TorrentStructure
    base_path: str
    piece_progress: list[bool]

    def __init__(self, torrent_hash: str, torrent_structure: TorrentStructure, base_path: str, piece_progress: list[bool]):
        self.torrent_hash = torrent_hash
        self.torrent_structure = torrent_structure
        self.base_path = base_path
        self.piece_progress = piece_progress

    def __repr__(self):
        return f"LiveTorrent(torrent_hash={self.torrent_hash}, torrent_structure={self.torrent_structure}, base_path={self.base_path}, piece_progress={self.piece_progress})"

    @classmethod
    def incomplete_from_torrent(cls, base_path: str, torrent: TorrentStructure):
        torrent_json = json.dumps(torrent.to_dict())
        torrent_hash = base62_sha1_hash_of(torrent_json.encode("utf-8"))
        piece_progress = [False] * len(torrent.pieces)
        live_torrent = cls(torrent_hash, torrent, base_path, piece_progress)
        return torrent_json, live_torrent

    def to_dict(self):
        data = {
            'torrent_hash': self.torrent_hash,
            'torrent_structure': self.torrent_structure.to_dict(),  # Convert Torrent to dict
            'base_path': self.base_path,
            'piece_progress': self.piece_progress
        }

        return data

    @classmethod
    def from_dict(cls, data: dict):
        torrent_structure = TorrentStructure.from_dict(data['torrent_structure'])  # Create Torrent from dict
        return cls(
            torrent_hash=data['torrent_hash'],
            torrent_structure=torrent_structure,
            base_path=data['base_path'],
            piece_progress=data['piece_progress']
        )

class EphemeralTorrentState:
    persistent_state: PersistentTorrentState
    torrent_json: str
    last_announced: None

    def __init__(self, s: PersistentTorrentState, torrent_json: str):
        self.persistent_state = s
        self.torrent_json = torrent_json

class EphemeralPeerState:
    peer_info: PeerInfo

    def __init__(self):
        self.peer_info = PeerInfo()