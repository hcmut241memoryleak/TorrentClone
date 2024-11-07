import os.path
import queue
import sys

from PyQt6.QtCore import QCommandLineParser, QCommandLineOption
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QFileDialog, QDialog, QHBoxLayout, \
    QLineEdit, QComboBox, QListWidget, QListWidgetItem

from node.io_thread import IoThread, TORRENT_STRUCTURE_FILE_SUFFIX
from node.torrenting import EphemeralTorrentState

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


class TorrentImportDialog(QDialog):
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

        # Path | Select file

        torrent_file_path_layout = QHBoxLayout()

        self.torrent_file_path_label = QLabel("Path")
        torrent_file_path_layout.addWidget(self.torrent_file_path_label)

        self.torrent_file_path_input = QLineEdit()
        self.torrent_file_path_input.setPlaceholderText("Path to torrent file")
        torrent_file_path_layout.addWidget(self.torrent_file_path_input)

        self.torrent_file_button = QPushButton("Select file")
        self.torrent_file_button.clicked.connect(self.select_torrent_file)
        torrent_file_path_layout.addWidget(self.torrent_file_button, 0)

        layout.addLayout(torrent_file_path_layout)

        # Save path | Select folder

        save_path_layout = QHBoxLayout()

        self.save_path_label = QLabel("Save to")
        save_path_layout.addWidget(self.save_path_label)

        self.save_path_input = QLineEdit()
        self.save_path_input.setPlaceholderText("Path to save torrent contents")
        save_path_layout.addWidget(self.save_path_input)

        self.save_path_button = QPushButton("Select folder")
        self.save_path_button.clicked.connect(self.select_save_path)
        save_path_layout.addWidget(self.save_path_button, 0)

        layout.addLayout(save_path_layout)

        # Create

        create_layout = QHBoxLayout()

        self.create_button = QPushButton("Import")
        self.create_button.setMinimumWidth(250)
        self.create_button.clicked.connect(self.create_torrent)
        create_layout.addWidget(self.create_button, 0)

        layout.addLayout(create_layout)

        self.setLayout(layout)
        self.setMinimumWidth(600)
        self.setWindowTitle("Torrent Creation")

    def select_torrent_file(self):
        options = QFileDialog.Option.ReadOnly
        path, _ = QFileDialog.getOpenFileName(self, "Select a file", "", f"Torrent Structure Files (*{TORRENT_STRUCTURE_FILE_SUFFIX});;All Files (*)", options=options)
        if path:
            self.torrent_file_path_input.setText(path)

    def select_save_path(self):
        path = QFileDialog.getExistingDirectory(self, "Select a folder", "")
        if path:
            self.save_path_input.setText(path)

    def create_torrent(self):
        name = self.torrent_naming_input.text()
        torrent_file_path = self.torrent_file_path_input.text()
        save_path = self.save_path_input.text()
        if torrent_file_path != "" and save_path != "":
            io_thread_inbox.put(("ui_import_torrent", torrent_file_path, save_path, name))
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
    def __init__(self, port_str: str, appdata_str: str):
        super().__init__()
        self.init_ui()

        self.io_thread = IoThread(io_thread_inbox, port_str, appdata_str)
        self.io_thread.ui_thread_inbox.connect(self.on_message_received)
        self.io_thread.io_thread_inbox = io_thread_inbox
        self.io_thread.start()

    def init_ui(self):
        layout = QVBoxLayout()

        top_buttons_layout = QHBoxLayout()
        self.create_torrent_button = QPushButton("Create torrent...")
        self.create_torrent_button.clicked.connect(self.open_torrent_creation_dialog)
        top_buttons_layout.addWidget(self.create_torrent_button)
        self.import_torrent_button = QPushButton("Import torrent...")
        self.import_torrent_button.clicked.connect(self.open_torrent_import_dialog)
        top_buttons_layout.addWidget(self.import_torrent_button)
        layout.addLayout(top_buttons_layout)

        magnet_link_layout = QHBoxLayout()
        self.magnet_link_input = QLineEdit()
        self.magnet_link_input.setPlaceholderText("magnet:?hash=...")
        magnet_link_layout.addWidget(self.magnet_link_input)
        self.add_magnet_link_button = QPushButton("Add magnet link")
        self.add_magnet_link_button.clicked.connect(self.on_add_magnet_link)
        magnet_link_layout.addWidget(self.add_magnet_link_button)
        layout.addLayout(magnet_link_layout)

        self.label = QLabel("Connecting to central tracker...")
        layout.addWidget(self.label)

        # Add the torrent list widget
        self.torrent_list = QListWidget()
        layout.addWidget(self.torrent_list)

        self.setLayout(layout)
        self.resize(640, 480)
        self.setMinimumSize(600, 400)

    def open_torrent_creation_dialog(self):
        TorrentCreationDialog().exec()

    def open_torrent_import_dialog(self):
        TorrentImportDialog().exec()

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

    def format_piece_states(self, piece_states: list[bool]) -> str:
        total_pieces = len(piece_states)
        completed_pieces = piece_states.count(True)

        if completed_pieces == total_pieces:
            return "Complete"

        completion_percentage = (completed_pieces / total_pieces) * 100
        return f"{completion_percentage:.1f}% ({completed_pieces}/{total_pieces} pcs)"

    def update_torrent_list(self, torrent_states: dict[str, EphemeralTorrentState]):
        self.torrent_list.clear()
        for sha256_hash, ephemeral_torrent_state in torrent_states.items():
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
    window_title = "HK241/MemoryLeak: TorrentClone (Qt UI)"

    app = QApplication(sys.argv)

    parser = QCommandLineParser()
    port_option = QCommandLineOption("port", "The port that other peers should connect to.", "port", "65433")
    appdata_option = QCommandLineOption("appdata", "App data location.", "appdata", "appdata")
    window_title_suffix_option = QCommandLineOption("window-title-suffix", "Window title suffix.", "suffix")
    parser.addOption(port_option)
    parser.addOption(appdata_option)
    parser.addOption(window_title_suffix_option)
    parser.process(app)

    main_window = MainWindow(parser.value(port_option), parser.value(appdata_option))
    if parser.isSet(window_title_suffix_option):
        window_title = f"{window_title} - {parser.value(window_title_suffix_option)}"
    main_window.setWindowTitle(window_title)
    main_window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
