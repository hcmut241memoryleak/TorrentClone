import uuid
import hashlib
import time
import socket

def to_base62(num):
    characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    base = len(characters)
    if num == 0:
        return characters[0]
    result = []
    while num:
        num, rem = divmod(num, base)
        result.append(characters[rem])
    return ''.join(reversed(result))

def generate_unique_id():
    uuid_base62 = to_base62(uuid.uuid4().int)
    timestamp_base62 = to_base62(int(time.time() * 1000))
    sha1_hash = to_base62(int.from_bytes(hashlib.sha1(socket.gethostname().encode()).digest(), 'big'))
    return f"{uuid_base62}-{timestamp_base62}-{sha1_hash}"

class PeerData:
    peer_id: str | None

    def __init__(self):
        self.peer_id = None