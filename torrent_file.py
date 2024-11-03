class TorrentFile:
    path: str
    byte_count: int
    byte_start: int

    def __init__(self, path, byte_count):
        self.path = path
        self.byte_count = byte_count
        self.byte_start = 0

    def set_byte_start(self, start):
        self.byte_start = start

    def __repr__(self):
        return f"File(path={self.path}, byte_count={self.byte_count}, byte_start={self.byte_start})"

class PieceSection:
    length: int
    file_index: int
    file_offset: int
    piece_offset: int

    def __init__(self, length, file_index, file_offset, piece_offset):
        self.length = length
        self.file_index = file_index
        self.file_offset = file_offset
        self.piece_offset = piece_offset

    def __repr__(self):
        return f"PieceSection(length={self.length}, file_index={self.file_index}, file_offset={self.file_offset}, piece_offset={self.piece_offset})"

class Piece:
    def __init__(self):
        self.sections = []

    def add_section(self, section):
        self.sections.append(section)

    def __repr__(self):
        return f"Piece(sections={self.sections})"

def pack_files_to_pieces(files: list[TorrentFile], piece_size):
    pieces = []
    current_piece = Piece()
    current_piece_position = 0

    current_start = 0
    for file_index, file in enumerate(files):
        file.set_byte_start(current_start)

        current_file_position = 0
        while current_file_position < file.byte_count:
            if (file.byte_count - current_file_position) >= (piece_size - current_piece_position): # need a new piece
                current_piece.add_section(PieceSection(piece_size - current_piece_position, file_index, current_file_position, current_piece_position))
                current_file_position += piece_size - current_piece_position
                pieces.append(current_piece)
                current_piece = Piece()
                current_piece_position = 0
            else:
                current_piece.add_section(PieceSection(file.byte_count - current_file_position, file_index, current_file_position, current_piece_position))
                current_piece_position += file.byte_count - current_file_position
                current_file_position = file.byte_count

        current_start += file.byte_count

    if len(current_piece.sections) > 0:
        pieces.append(current_piece)

    return pieces
