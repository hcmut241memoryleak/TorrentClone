from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QFileDialog, QDialog, QHBoxLayout, \
    QLineEdit, QComboBox

import sys
import queue

from node.io_thread import IoThread

io_thread_inbox = queue.Queue()

class TorrentCreationDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Path | Select file | Select folder

        path_selection_layout = QHBoxLayout()

        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Path...")
        path_selection_layout.addWidget(self.path_input)

        self.file_button = QPushButton("Select file")
        self.file_button.clicked.connect(self.select_file)
        path_selection_layout.addWidget(self.file_button, 0)

        self.folder_button = QPushButton("Select folder")
        self.folder_button.clicked.connect(self.select_folder)
        path_selection_layout.addWidget(self.folder_button, 0)

        layout.addLayout(path_selection_layout)

        # Piece size: [combo box] | Create

        create_layout = QHBoxLayout()

        self.piece_size_combobox_label = QLabel("Piece size")
        create_layout.addWidget(self.piece_size_combobox_label, 0)

        self.piece_size_combobox = QComboBox()
        self.piece_size_combobox.addItem('128 KiB')
        self.piece_size_combobox.addItem('256 KiB')
        self.piece_size_combobox.addItem('512 KiB')
        self.piece_size_combobox.addItem('1 MiB')
        self.piece_size_combobox.setCurrentIndex(1)
        create_layout.addWidget(self.piece_size_combobox, 0)

        create_layout.addWidget(QWidget(), 1)

        self.create_button = QPushButton("Create")
        self.create_button.setMinimumWidth(250)
        self.create_button.clicked.connect(self.create)
        create_layout.addWidget(self.create_button, 0)

        layout.addLayout(create_layout)

        self.setLayout(layout)
        self.setMinimumWidth(600)
        self.setWindowTitle("Torrent Creation")

    def select_file(self):
        options = QFileDialog.Option.ReadOnly
        path, _ = QFileDialog.getOpenFileName(self, "Select a file", "", "All Files (*)", options=options)
        if path:
            self.path_input.setText(path)

    def select_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select a folder", "")
        if path:
            self.path_input.setText(path)

    def create(self):
        path = self.path_input.text()
        if path != "":
            piece_sizes = [
                2 ** 17, # 128 KiB
                2 ** 18, # 256 KiB
                2 ** 19, # 512 KiB
                2 ** 20 # 1 MiB
            ]
            piece_size = piece_sizes[self.piece_size_combobox.currentIndex()]
            io_thread_inbox.put(("ui_create_torrent", path, piece_size))
            self.close()

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

        self.io_thread = IoThread(io_thread_inbox)
        self.io_thread.ui_thread_inbox_ready.connect(self.on_message_received)
        self.io_thread.io_thread_inbox = io_thread_inbox
        self.io_thread.start()

    def init_ui(self):
        layout = QVBoxLayout()

        self.torrent_button = QPushButton("Create torrent...")
        self.torrent_button.clicked.connect(self.open_torrent_creation_dialog)
        layout.addWidget(self.torrent_button)

        magnet_link_layout = QHBoxLayout()
        self.magnet_link_input = QLineEdit()
        self.magnet_link_input.setPlaceholderText("magnet:?hash=...")
        magnet_link_layout.addWidget(self.magnet_link_input)
        self.add_magnet_link_button = QPushButton("Add magnet link")
        self.add_magnet_link_button.clicked.connect(self.on_add_magnet_link)
        magnet_link_layout.addWidget(self.add_magnet_link_button)

        self.label = QLabel("Waiting for messages...")
        layout.addLayout(magnet_link_layout)
        layout.addWidget(self.label)

        self.setLayout(layout)
        self.setWindowTitle("HK241/MemoryLeak: TorrentClone (Qt UI)")
        self.setFixedSize(1280, 720)

    def open_torrent_creation_dialog(self):
        dialog = TorrentCreationDialog()
        dialog.exec()

    def on_add_magnet_link(self):
        io_thread_inbox.put(("add_magnet_link", self.magnet_link_input.text()))

    def on_message_received(self, message):
        self.label.setText(f"Received: {message}")

    def closeEvent(self, event):
        io_thread_inbox.put("ui_quit")
        self.io_thread.wait()  # Wait for the I/O thread to finish
        event.accept()

def main():
    # files = [
    #     TorrentFile("hi.txt", 1572000),
    #     TorrentFile("bye.txt", 200),
    #     TorrentFile("lol.txt", 864000),
    # ]
    #
    # for piece in pack_files_to_pieces(files, 2 ** 19):
    #     print(f"{piece}")

    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()