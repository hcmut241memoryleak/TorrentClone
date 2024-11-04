import os.path
import queue
import sys

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QFileDialog, QDialog, QHBoxLayout, \
    QLineEdit, QComboBox, QListWidget, QListWidgetItem

from node.io_thread import IoThread
from node.torrenting import EphemeralTorrentState, PieceState

io_thread_inbox = queue.Queue()


class IoErrorDialog(QDialog):
    def __init__(self, e: str):
        self.error_string = e
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.label = QLabel("The I/O thread encountered an error:")
        layout.addWidget(self.label)

        self.label2 = QLabel(self.error_string)
        layout.addWidget(self.label2)

        self.setLayout(layout)
        self.setMinimumWidth(600)
        self.setWindowTitle("I/O thread error")


class TorrentCreationDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # "Name" | Name
        torrent_naming_layout = QHBoxLayout()
        self.torrent_naming_label = QLabel("Name")
        torrent_naming_layout.addWidget(self.torrent_naming_label)

        self.torrent_naming_input = QLineEdit()
        self.torrent_naming_input.setPlaceholderText("Name (uses file/folder name if left empty)")
        torrent_naming_layout.addWidget(self.torrent_naming_input)

        layout.addLayout(torrent_naming_layout)

        # Path | Select file | Select folder

        path_selection_layout = QHBoxLayout()

        self.path_label = QLabel("Path")
        path_selection_layout.addWidget(self.path_label)

        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Path to file or folder")
        path_selection_layout.addWidget(self.path_input)

        self.file_button = QPushButton("Select file")
        self.file_button.clicked.connect(self.select_file)
        path_selection_layout.addWidget(self.file_button, 0)

        self.folder_button = QPushButton("Select folder")
        self.folder_button.clicked.connect(self.select_folder)
        path_selection_layout.addWidget(self.folder_button, 0)

        layout.addLayout(path_selection_layout)

        # "Piece size:" | [combo box] | Create

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
        self.create_button.clicked.connect(self.create_torrent)
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

    def create_torrent(self):
        path = self.path_input.text()
        if path != "":
            piece_sizes = [
                2 ** 17,  # 128 KiB
                2 ** 18,  # 256 KiB
                2 ** 19,  # 512 KiB
                2 ** 20  # 1 MiB
            ]
            piece_size = piece_sizes[self.piece_size_combobox.currentIndex()]
            torrent_name = self.torrent_naming_input.text()
            if len(torrent_name) == 0:
                torrent_name = os.path.basename(path)
            io_thread_inbox.put(("ui_create_torrent", path, torrent_name, piece_size))
            self.close()


class TorrentListItemWidget(QWidget):
    def __init__(self, torrent_name: str, piece_state: str):
        super().__init__()

        layout = QVBoxLayout()

        # Torrent name label (larger font)
        self.name_label = QLabel(torrent_name)
        name_font = QFont()
        name_font.setPointSize(12)  # Set a larger font size for the name
        name_font.setBold(True)
        self.name_label.setFont(name_font)
        layout.addWidget(self.name_label)

        # Piece state label (smaller font)
        self.state_label = QLabel(piece_state)
        state_font = QFont()
        state_font.setPointSize(10)
        self.state_label.setFont(state_font)
        layout.addWidget(self.state_label)

        self.setLayout(layout)


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

        self.io_thread = IoThread(io_thread_inbox)
        self.io_thread.ui_thread_inbox.connect(self.on_message_received)
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

        self.label = QLabel("Connecting to central tracker...")
        layout.addLayout(magnet_link_layout)
        layout.addWidget(self.label)

        # Add the torrent list widget
        self.torrent_list = QListWidget()
        layout.addWidget(self.torrent_list)

        self.setLayout(layout)
        self.setWindowTitle("HK241/MemoryLeak: TorrentClone (Qt UI)")
        self.resize(1280, 720)
        self.setMinimumSize(600, 400)

    def open_torrent_creation_dialog(self):
        TorrentCreationDialog().exec()

    def on_add_magnet_link(self):
        io_thread_inbox.put(("add_magnet_link", self.magnet_link_input.text()))

    def on_message_received(self, message):
        message_type = message[0]
        if message_type == "io_error":
            _, error_string = message
            IoErrorDialog(error_string).exec()
        elif message == "io_hi":
            self.label.setText(f"I/O thread has connected to the central tracker and says hi.")
        elif message_type == "io_peers_changed":
            pass
        elif message_type == "io_torrents_changed":
            _, torrents = message
            self.update_torrent_list(torrents)

    def format_piece_states(self, piece_states: list[PieceState]) -> str:
        total_pieces = len(piece_states)
        completed_pieces = piece_states.count(PieceState.COMPLETE)

        if completed_pieces == total_pieces:
            return "Complete"

        pending_download = piece_states.count(PieceState.PENDING_DOWNLOAD)
        pending_check = piece_states.count(PieceState.PENDING_CHECK)

        completion_percentage = (completed_pieces / total_pieces) * 100

        status_parts = [f"{completion_percentage:.1f}%"]
        if pending_download > 0:
            status_parts.append(f"{pending_download} pieces pending download")
        if pending_check > 0:
            status_parts.append(f"{pending_check} pieces pending recheck")

        return " (" + ", ".join(status_parts) + ")"

    def update_torrent_list(self, torrent_states: dict[str, EphemeralTorrentState]):
        self.torrent_list.clear()
        for torrent_hash, ephemeral_torrent_state in torrent_states.items():
            piece_state = self.format_piece_states(ephemeral_torrent_state.persistent_state.piece_states)
            item_widget = TorrentListItemWidget(ephemeral_torrent_state.persistent_state.torrent_name, piece_state)

            list_item = QListWidgetItem(self.torrent_list)
            list_item.setSizeHint(item_widget.sizeHint())
            self.torrent_list.addItem(list_item)
            self.torrent_list.setItemWidget(list_item, item_widget)

    def closeEvent(self, event):
        io_thread_inbox.put("ui_quit")
        self.io_thread.wait()  # Wait for the I/O thread to finish
        event.accept()


def main():
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
