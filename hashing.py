import hashlib

base62_characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def to_base62(num):
    base = len(base62_characters)
    if num == 0:
        return base62_characters[0]
    result = []
    while num:
        num, rem = divmod(num, base)
        result.append(base62_characters[rem])
    return ''.join(reversed(result))


def is_valid_base62_sha256_hash(s: str):
    return len(s) == 43 and not any(c not in base62_characters for c in s)

def win_filesys_escape_uppercase(s: str) -> str:
    escaped = []
    for char in s:
        if char.isupper():
            escaped.append(f'-{char.lower()}')
        else:
            escaped.append(char)
    return ''.join(escaped)


def win_filesys_unescape_uppercase(s: str) -> str:
    unescaped = []
    i = 0
    while i < len(s):
        if s[i] == '-' and i + 1 < len(s):
            unescaped.append(s[i + 1].upper())
            i += 2
        else:
            unescaped.append(s[i])
            i += 1
    return ''.join(unescaped)


def base62_sha1_hash_of(b: bytes):
    return to_base62(int.from_bytes(hashlib.sha1(b).digest(), 'big'))


def base62_sha256_hash_of(b: bytes):
    return to_base62(int.from_bytes(hashlib.sha256(b).digest(), 'big'))
