class TorrentFile:
    path: str
    byte_count: int

    def __init__(self, path, byte_count):
        self.path = path
        self.byte_count = byte_count

    def __repr__(self):
        return f"File(path={self.path}, byte_count={self.byte_count})"

    def to_dict(self):
        return {
            'path': self.path,
            'byte_count': self.byte_count
        }

    @classmethod
    def from_dict(cls, data: dict):
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

    def to_dict(self):
        return {
            'length': self.length,
            'file_index': self.file_index,
            'file_offset': self.file_offset
        }

    @classmethod
    def from_dict(cls, data: dict):
        return cls(length=data['length'], file_index=data['file_index'], file_offset=data['file_offset'])


class Piece:
    sections: list[PieceSection]
    base_62_sha1: str

    def __init__(self):
        self.sections = []
        self.base_62_sha1 = ""

    def __repr__(self):
        return f"Piece(sections={self.sections}, base_62_sha1={self.base_62_sha1})"

    def to_dict(self):
        sections_dict = [section.to_dict() for section in self.sections]
        return {
            'sections': sections_dict,
            'base_62_sha1': self.base_62_sha1
        }

    @classmethod
    def from_dict(cls, data: dict):
        piece = cls()
        piece.base_62_sha1 = data['base_62_sha1']
        piece.sections = [PieceSection.from_dict(section_data) for section_data in data['sections']]
        return piece


class TorrentStructure:
    files: list[TorrentFile]
    piece_size: int
    pieces: list[Piece]

    def __init__(self, f: list[TorrentFile], s: int, p: list[Piece]):
        self.files = f
        self.piece_size = s
        self.pieces = p

    def __repr__(self):
        return f"Torrent(files={self.files}, piece_size={self.piece_size}, pieces={self.pieces})"

    def to_dict(self):
        files_dict = [file.to_dict() for file in self.files]
        pieces_dict = [piece.to_dict() for piece in self.pieces]
        return {
            'files': files_dict,
            'piece_size': self.piece_size,
            'pieces': pieces_dict
        }

    @classmethod
    def from_dict(cls, data: dict):
        files = [TorrentFile.from_dict(file_data) for file_data in data['files']]
        piece_size = data['piece_size']
        pieces = [Piece.from_dict(piece_data) for piece_data in data['pieces']]
        return cls(files, piece_size, pieces)


def pack_files_to_pieces(files: list[TorrentFile], piece_size):
    pieces = []
    current_piece = Piece()
    current_piece_position = 0

    for file_index, file in enumerate(files):
        current_file_position = 0
        while current_file_position < file.byte_count:
            if (file.byte_count - current_file_position) >= (piece_size - current_piece_position):  # need a new piece
                current_piece.sections.append(
                    PieceSection(piece_size - current_piece_position, file_index, current_file_position))
                current_file_position += piece_size - current_piece_position
                pieces.append(current_piece)
                current_piece = Piece()
                current_piece_position = 0
            else:
                current_piece.sections.append(
                    PieceSection(file.byte_count - current_file_position, file_index, current_file_position))
                current_piece_position += file.byte_count - current_file_position
                current_file_position = file.byte_count

    if len(current_piece.sections) > 0:
        pieces.append(current_piece)

    return pieces
