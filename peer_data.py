import uuid
import time
import socket

from hashing import to_base62, base62_sha1_hash_of

def generate_unique_id():
    uuid_base62 = to_base62(uuid.uuid4().int)
    timestamp_base62 = to_base62(int(time.time() * 1000))
    sha1_hash = base62_sha1_hash_of(socket.gethostname().encode())
    return f"{uuid_base62}-{timestamp_base62}-{sha1_hash}"

class PeerData:
    peer_id: str | None

    def __init__(self):
        self.peer_id = None