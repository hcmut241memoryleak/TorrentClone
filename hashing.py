import hashlib

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

def base62_sha1_hash_of(b: bytes):
    return to_base62(int.from_bytes(hashlib.sha1(b).digest(), 'big'))