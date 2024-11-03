import json

class TorrentFile:
    path: str
    byte_count: int

    def __init__(self, path, byte_count):
        self.path = path
        self.byte_count = byte_count

    def __repr__(self):
        return f"File(path={self.path}, byte_count={self.byte_count})"

    def to_json(self):
        return json.dumps({
            'path': self.path,
            'byte_count': self.byte_count
        })

    @classmethod
    def from_json(cls, json_str: str):
        data = json.loads(json_str)
        return cls(path=data['path'], byte_count=data['byte_count'])

class PieceSection:
    length: int
    file_index: int
    file_offset: int

    def __init__(self, length, file_index, file_offset):
        self.length = length
        self.file_index = file_index
        self.file_offset = file_offset

    def __repr__(self):
        return f"PieceSection(length={self.length}, file_index={self.file_index}, file_offset={self.file_offset})"

    def to_json(self):
        return json.dumps({
            'length': self.length,
            'file_index': self.file_index,
            'file_offset': self.file_offset
        })

    @classmethod
    def from_json(cls, json_str: str):
        data = json.loads(json_str)
        return cls(length=data['length'], file_index=data['file_index'], file_offset=data['file_offset'])

class Piece:
    sections: list[PieceSection]
    base_62_sha1: str

    def __init__(self):
        self.sections = []
        self.base_62_sha1 = ""

    def add_section(self, section):
        self.sections.append(section)

    def set_base_62_sha1(self, h: str):
        self.base_62_sha1 = h

    def __repr__(self):
        return f"Piece(sections={self.sections}, base_62_sha1={self.base_62_sha1})"

    def to_json(self):
        sections_json = [section.to_json() for section in self.sections]
        return json.dumps({
            'sections': sections_json,
            'base_62_sha1': self.base_62_sha1
        })

    @classmethod
    def from_json(cls, json_str: str):
        data = json.loads(json_str)
        piece = cls()
        piece.base_62_sha1 = data['base_62_sha1']
        piece.sections = [PieceSection.from_json(section_json) for section_json in data['sections']]
        return piece

class Torrent:
    files: list[TorrentFile]
    Piece: list[Piece]

    def __init__(self, f: list[TorrentFile], p: list[Piece]):
        self.files = f
        self.pieces = p

    def __repr__(self):
        return f"Torrent(files={self.files}, pieces={self.pieces})"

    def to_json(self):
        files_json = [file.to_json() for file in self.files]
        pieces_json = [piece.to_json() for piece in self.pieces]
        return json.dumps({
            'files': files_json,
            'pieces': pieces_json
        })

    @classmethod
    def from_json(cls, json_str: str):
        data = json.loads(json_str)
        files = [TorrentFile.from_json(file_json) for file_json in data['files']]
        pieces = [Piece.from_json(piece_json) for piece_json in data['pieces']]
        torrent = cls(files, pieces)
        return torrent

def pack_files_to_pieces(files: list[TorrentFile], piece_size):
    pieces = []
    current_piece = Piece()
    current_piece_position = 0

    for file_index, file in enumerate(files):
        current_file_position = 0
        while current_file_position < file.byte_count:
            if (file.byte_count - current_file_position) >= (piece_size - current_piece_position): # need a new piece
                current_piece.add_section(PieceSection(piece_size - current_piece_position, file_index, current_file_position))
                current_file_position += piece_size - current_piece_position
                pieces.append(current_piece)
                current_piece = Piece()
                current_piece_position = 0
            else:
                current_piece.add_section(PieceSection(file.byte_count - current_file_position, file_index, current_file_position))
                current_piece_position += file.byte_count - current_file_position
                current_file_position = file.byte_count

    if len(current_piece.sections) > 0:
        pieces.append(current_piece)

    return pieces
