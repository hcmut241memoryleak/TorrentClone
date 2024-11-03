class File:
    def __init__(self, filename, file_size):
        self.filename = filename
        self.file_size = file_size
        self.byte_range = None

    def set_byte_range(self, start, end):
        self.byte_range = (start, end)

    def __repr__(self):
        return f"File(filename={self.filename}, file_size={self.file_size}, byte_range={self.byte_range})"


def pack_files(files, piece_size):
    packed_files = []
    current_start = 0

    for file in files:
        file_size = file.file_size
        remaining_size = file_size
        pieces = []

        while remaining_size > 0:
            piece_end = min(current_start + piece_size - 1, current_start + remaining_size - 1)
            pieces.append((current_start, piece_end))
            remaining_size -= (piece_end - current_start + 1)
            current_start = piece_end + 1

        packed_files.append((file, pieces))

    for file, pieces in packed_files:
        file.set_byte_range(pieces[0][0], pieces[-1][1])

    return files
