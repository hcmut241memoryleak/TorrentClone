import socket
import time
import uuid

from hashing import to_base62, base62_sha1_hash_of


def generate_unique_id():
    uuid_base62 = to_base62(uuid.uuid4().int)
    timestamp_base62 = to_base62(int(time.time() * 1000))
    sha1_hash = base62_sha1_hash_of(socket.gethostname().encode("utf-8"))
    return f"{uuid_base62}-{timestamp_base62}-{sha1_hash}"


class PeerInfo:
    peer_id: str | None
    peer_port: int | None

    def __init__(self):
        self.peer_id = None
        self.peer_port = None

    def __repr__(self):
        return f"PeerInfo(peer_id={self.peer_id}, peer_port={self.peer_port})"

    def is_filled(self):
        return self.peer_id is not None and self.peer_port is not None

    def to_dict(self):
        return {
            'peer_id': self.peer_id,
            'peer_port': self.peer_port
        }

    @classmethod
    def from_dict(cls, data: dict):
        instance = cls()
        instance.peer_id = data.get('peer_id')
        instance.peer_port = data.get('peer_port')
        return instance
