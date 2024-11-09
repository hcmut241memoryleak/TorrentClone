class UiTorrentState:
    sha256_hash: str
    torrent_name: str
    piece_states: list[bool]
    seeder_count: int

    def __init__(self, sha256_hash: str, torrent_name: str, piece_states: list[bool], seeder_count: int):
        self.sha256_hash = sha256_hash
        self.torrent_name = torrent_name
        self.piece_states = piece_states
        self.seeder_count = seeder_count

class UiTorrentHashImportState:
    sha256_hash: str
    torrent_name: str
    can_be_requested: bool

    def __init__(self, sha256_hash: str, torrent_name: str, can_be_requested: bool):
        self.sha256_hash = sha256_hash
        self.torrent_name = torrent_name
        self.can_be_requested = can_be_requested