class TorrentFile:
    path: str
    byte_count: int

    def __init__(self, path, byte_count):
        self.path = path
        self.byte_count = byte_count

    def __repr__(self):
        return f"File(path={self.path}, byte_count={self.byte_count})"

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
