import json

from hashing import base62_sha1_hash_of
from torrent_data import Torrent, TorrentFile

class LiveTorrent:
    torrent_json: str
    torrent_hash: str
    torrent_data: Torrent
    base_path: str

    def __init__(self, torrent_json: str, torrent_hash: str, torrent_data: Torrent, base_path: str):
        self.torrent_json = torrent_json
        self.torrent_hash = torrent_hash
        self.torrent_data = torrent_data
        self.base_path = base_path

    def __repr__(self):
        return f"LiveTorrent(torrent_hash={self.torrent_hash}, torrent_data={self.torrent_data}, base_path={self.base_path})"

    @classmethod
    def from_torrent(cls, base_path: str, torrent: Torrent):
        torrent_json = torrent.to_json()
        torrent_hash = base62_sha1_hash_of(torrent_json.encode("utf-8"))
        live_torrent = cls(torrent_json, torrent_hash, torrent, base_path)
        return live_torrent

    def to_json(self, include_torrent_json: bool = True):
        data = {
            'torrent_hash': self.torrent_hash,
            'torrent_data': self.torrent_data.to_json(),  # Assuming Torrent has a to_json method
            'base_path': self.base_path
        }
        if include_torrent_json:
            data['torrent_json'] = self.torrent_json

        return json.dumps(data)

    @classmethod
    def from_json(cls, json_str: str):
        data = json.loads(json_str)
        torrent_data = Torrent.from_json(data['torrent_data'])  # Assuming Torrent has a from_json method
        return cls(
            torrent_json=data.get('torrent_json', ''),
            torrent_hash=data['torrent_hash'],
            torrent_data=torrent_data,
            base_path=data['base_path']
        )