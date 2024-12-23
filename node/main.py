import os.path
import queue
import sys

from PyQt6.QtCore import QCommandLineParser, QCommandLineOption, Qt
from PyQt6.QtGui import QFont, QAction
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QFileDialog, QDialog, QHBoxLayout, \
    QLineEdit, QComboBox, QListWidget, QListWidgetItem, QMenu, QStyle

from hashing import win_filesys_escape_uppercase, is_valid_base62_sha256_hash
from node.io_thread import IoThread, TORRENT_STRUCTURE_FILE_SUFFIX
from node.torrenting import EphemeralTorrentState
from node.ui_messages import UiTorrentState, UiTorrentHashImportState

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
    piece_size_choices: dict[int, str] = {
        2 ** 17: "128 KiB",
        2 ** 18: "256 KiB",
        2 ** 19: "512 KiB",
        2 ** 20: "1 MiB",
        2 ** 21: "2 MiB"
    }
    default_piece_size_choice: int = 2

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
        for piece_size_name in self.piece_size_choices.values():
            self.piece_size_combobox.addItem(piece_size_name)
        self.piece_size_combobox.setCurrentIndex(self.default_piece_size_choice)
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
            piece_size = list(self.piece_size_choices.keys())[self.piece_size_combobox.currentIndex()]
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
        self.setWindowTitle("Torrent Import")

    def select_torrent_file(self):
        options = QFileDialog.Option.ReadOnly
        path, _ = QFileDialog.getOpenFileName(self, "Select a file", "",
                                              f"Torrent Structure Files (*{TORRENT_STRUCTURE_FILE_SUFFIX});;All Files (*)",
                                              options=options)
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


class TorrentHashImportDialog(QDialog):
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

        torrent_hash_input_layout = QHBoxLayout()

        self.torrent_hash_label = QLabel("Hash")
        torrent_hash_input_layout.addWidget(self.torrent_hash_label)

        self.torrent_hash_input = QLineEdit()
        self.torrent_hash_input.setPlaceholderText("Torrent hash")
        torrent_hash_input_layout.addWidget(self.torrent_hash_input)

        layout.addLayout(torrent_hash_input_layout)

        # Save path | Select folder

        save_path_layout = QHBoxLayout()

        self.save_path_label = QLabel("Save torrent contents to")
        save_path_layout.addWidget(self.save_path_label)

        self.save_path_input = QLineEdit()
        self.save_path_input.setPlaceholderText("Path to save torrent contents")
        save_path_layout.addWidget(self.save_path_input)

        self.save_path_button = QPushButton("Select folder")
        self.save_path_button.clicked.connect(self.select_save_path)
        save_path_layout.addWidget(self.save_path_button, 0)

        layout.addLayout(save_path_layout)

        # Import

        import_layout = QHBoxLayout()

        self.import_button = QPushButton("Import by hash")
        self.import_button.setMinimumWidth(250)
        self.import_button.clicked.connect(self.import_hash)
        import_layout.addWidget(self.import_button, 0)

        layout.addLayout(import_layout)

        self.setLayout(layout)
        self.setMinimumWidth(600)
        self.setWindowTitle("Torrent Import by Hash")

    def select_save_path(self):
        path = QFileDialog.getExistingDirectory(self, "Select a folder", "")
        if path:
            self.save_path_input.setText(path)

    def import_hash(self):
        name = self.torrent_naming_input.text()
        torrent_hash = self.torrent_hash_input.text()
        save_path = self.save_path_input.text()
        if is_valid_base62_sha256_hash(torrent_hash) and save_path != "":
            io_thread_inbox.put(("ui_import_torrent_by_hash", torrent_hash, name, save_path))
            self.close()


class TorrentExportDialog(QDialog):
    torrent_hash: str
    torrent_name: str

    def __init__(self, torrent_hash: str, torrent_name: str):
        super().__init__()

        self.torrent_hash = torrent_hash
        self.torrent_name = torrent_name

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.torrent_naming_label = QLabel(f"Save \"{self.torrent_name}\" to...")
        layout.addWidget(self.torrent_naming_label)

        # Path | Select file

        torrent_file_path_layout = QHBoxLayout()

        self.torrent_file_path_label = QLabel("Path")
        torrent_file_path_layout.addWidget(self.torrent_file_path_label)

        self.torrent_file_path_input = QLineEdit()
        self.torrent_file_path_input.setPlaceholderText("Path to save to torrent file")
        torrent_file_path_layout.addWidget(self.torrent_file_path_input)

        self.torrent_file_button = QPushButton("Select")
        self.torrent_file_button.clicked.connect(self.select_output_torrent_file)
        torrent_file_path_layout.addWidget(self.torrent_file_button, 0)

        layout.addLayout(torrent_file_path_layout)

        self.export_button = QPushButton("Export")
        self.export_button.setMinimumWidth(250)
        self.export_button.clicked.connect(self.export_torrent)

        layout.addWidget(self.export_button)

        self.setLayout(layout)
        self.setMinimumWidth(600)
        self.setWindowTitle("Torrent Export")

    def select_output_torrent_file(self):
        dialog_caption = f"Select a location to save \"{self.torrent_name}\""
        default_filename = f"{win_filesys_escape_uppercase(self.torrent_hash)}{TORRENT_STRUCTURE_FILE_SUFFIX}"
        file_filter = f"Torrent Structure Files (*{TORRENT_STRUCTURE_FILE_SUFFIX});;All Files (*)"
        options = QFileDialog.Option.ShowDirsOnly
        path, _ = QFileDialog.getSaveFileName(self, dialog_caption, default_filename, file_filter, options=options)
        if path:
            self.torrent_file_path_input.setText(path)

    def export_torrent(self):
        torrent_file_path = self.torrent_file_path_input.text()
        if torrent_file_path != "":
            io_thread_inbox.put(("ui_export_torrent", self.torrent_hash, torrent_file_path))
            self.close()


class TorrentRenameDialog(QDialog):
    torrent_hash: str
    torrent_name: str

    def __init__(self, torrent_hash: str, torrent_name: str):
        super().__init__()

        self.torrent_hash = torrent_hash
        self.torrent_name = torrent_name

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.torrent_naming_label = QLabel(f"Rename \"{self.torrent_name}\" to...")
        layout.addWidget(self.torrent_naming_label)

        new_name_layout = QHBoxLayout()

        self.new_name_label = QLabel("Rename to")
        new_name_layout.addWidget(self.new_name_label)

        self.new_name_input = QLineEdit()
        self.new_name_input.setPlaceholderText("New name")
        new_name_layout.addWidget(self.new_name_input)

        layout.addLayout(new_name_layout)

        self.rename_button = QPushButton("Rename")
        self.rename_button.setMinimumWidth(250)
        self.rename_button.clicked.connect(self.rename_torrent)

        layout.addWidget(self.rename_button)

        self.setLayout(layout)
        self.setMinimumWidth(600)
        self.setWindowTitle("Torrent Rename")

    def rename_torrent(self):
        new_name = self.new_name_input.text()
        if new_name != "":
            io_thread_inbox.put(("ui_rename_torrent", self.torrent_hash, new_name))
            self.close()


class TorrentRemoveDialog(QDialog):
    torrent_hash: str
    torrent_name: str

    def __init__(self, torrent_hash: str, torrent_name: str):
        super().__init__()

        self.torrent_hash = torrent_hash
        self.torrent_name = torrent_name

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.label = QLabel(f"Remove torrent \"{self.torrent_name}\"?")
        layout.addWidget(self.label)

        buttons_layout = QHBoxLayout()

        self.remove_button = QPushButton("Remove")
        self.remove_button.setMinimumWidth(250)
        self.remove_button.clicked.connect(self.remove_torrent)
        buttons_layout.addWidget(self.remove_button)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setMinimumWidth(250)
        self.cancel_button.clicked.connect(self.cancel)
        buttons_layout.addWidget(self.cancel_button)

        layout.addLayout(buttons_layout)

        self.setLayout(layout)
        self.setMinimumWidth(600)
        self.setWindowTitle("Torrent Removal")

    def cancel(self):
        self.close()

    def remove_torrent(self):
        io_thread_inbox.put(("ui_remove_torrent", self.torrent_hash))
        self.close()


class TorrentHashImportRenameDialog(QDialog):
    torrent_hash: str
    torrent_name: str

    def __init__(self, torrent_hash: str, torrent_name: str):
        super().__init__()

        self.torrent_hash = torrent_hash
        self.torrent_name = torrent_name

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.torrent_naming_label = QLabel(f"Rename \"{self.torrent_name}\" to...")
        layout.addWidget(self.torrent_naming_label)

        new_name_layout = QHBoxLayout()

        self.new_name_label = QLabel("Rename to")
        new_name_layout.addWidget(self.new_name_label)

        self.new_name_input = QLineEdit()
        self.new_name_input.setPlaceholderText("New name")
        new_name_layout.addWidget(self.new_name_input)

        layout.addLayout(new_name_layout)

        self.rename_button = QPushButton("Rename")
        self.rename_button.setMinimumWidth(250)
        self.rename_button.clicked.connect(self.rename_torrent)

        layout.addWidget(self.rename_button)

        self.setLayout(layout)
        self.setMinimumWidth(600)
        self.setWindowTitle("Torrent Hash Import Rename")

    def rename_torrent(self):
        new_name = self.new_name_input.text()
        if new_name != "":
            io_thread_inbox.put(("ui_rename_torrent_hash_import", self.torrent_hash, new_name))
            self.close()


class TorrentHashImportRemoveDialog(QDialog):
    torrent_hash: str
    torrent_name: str

    def __init__(self, torrent_hash: str, torrent_name: str):
        super().__init__()

        self.torrent_hash = torrent_hash
        self.torrent_name = torrent_name

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.label = QLabel(f"Remove torrent import \"{self.torrent_name}\"?")
        layout.addWidget(self.label)

        buttons_layout = QHBoxLayout()

        self.remove_button = QPushButton("Remove")
        self.remove_button.setMinimumWidth(250)
        self.remove_button.clicked.connect(self.remove_torrent)
        buttons_layout.addWidget(self.remove_button)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setMinimumWidth(250)
        self.cancel_button.clicked.connect(self.cancel)
        buttons_layout.addWidget(self.cancel_button)

        layout.addLayout(buttons_layout)

        self.setLayout(layout)
        self.setMinimumWidth(600)
        self.setWindowTitle("Torrent Hash Import Removal")

    def cancel(self):
        self.close()

    def remove_torrent(self):
        io_thread_inbox.put(("ui_remove_torrent_hash_import", self.torrent_hash))
        self.close()


class TorrentListWidgetTorrentWidget(QWidget):
    def __init__(self, torrent_name: str, piece_state_str: str):
        super().__init__()

        layout = QVBoxLayout()

        # Torrent name label (larger font)
        self.name_label = QLabel(torrent_name)
        name_font = QFont()
        name_font.setPointSize(12)
        name_font.setBold(True)
        self.name_label.setFont(name_font)
        layout.addWidget(self.name_label)

        # Piece state label (smaller font)
        self.state_label = QLabel(piece_state_str)
        state_font = QFont()
        state_font.setPointSize(10)
        self.state_label.setFont(state_font)
        layout.addWidget(self.state_label)

        self.setLayout(layout)


class TorrentListWidgetTorrentItem(QListWidgetItem):
    torrent_hash: str
    torrent_name: str

    def __init__(self, parent, torrent_hash: str, torrent_name: str):
        super().__init__(parent)

        self.torrent_hash = torrent_hash
        self.torrent_name = torrent_name


class TorrentListWidgetTorrentHashImportWidget(QWidget):
    def __init__(self, torrent_name: str, piece_state_str: str):
        super().__init__()

        layout = QVBoxLayout()

        # Torrent name label (larger font)
        self.name_label = QLabel(torrent_name)
        name_font = QFont()
        name_font.setPointSize(12)
        name_font.setBold(True)
        self.name_label.setFont(name_font)
        layout.addWidget(self.name_label)

        # Piece state label (smaller font)
        self.state_label = QLabel(piece_state_str)
        state_font = QFont()
        state_font.setPointSize(10)
        self.state_label.setFont(state_font)
        layout.addWidget(self.state_label)

        self.setLayout(layout)


class TorrentListWidgetTorrentHashImportItem(QListWidgetItem):
    torrent_hash: str
    torrent_name: str

    def __init__(self, parent, torrent_hash: str, torrent_name: str):
        super().__init__(parent)

        self.torrent_hash = torrent_hash
        self.torrent_name = torrent_name


class TorrentListWidget(QListWidget):
    def __init__(self):
        super().__init__()

    def contextMenuEvent(self, event):
        item = self.itemAt(event.pos())
        if not item:
            return

        if isinstance(item, TorrentListWidgetTorrentItem):
            torrent_hash = item.torrent_hash
            torrent_name = item.torrent_name

            context_menu = QMenu(self)
            copy_hash_action = QAction(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogNewFolder), "Copy torrent hash",
                                  self)
            open_action = QAction(self.style().standardIcon(QStyle.StandardPixmap.SP_DirOpenIcon), "Open file location",
                                  self)
            export_action = QAction(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton),
                                    "Export torrent", self)
            rename_action = QAction(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogNewFolder),
                                    "Rename torrent", self)
            remove_action = QAction(self.style().standardIcon(QStyle.StandardPixmap.SP_TrashIcon), "Remove torrent",
                                    self)

            copy_hash_action.triggered.connect(lambda: QApplication.clipboard().setText(torrent_hash))
            open_action.triggered.connect(lambda: self.open_torrent_location(torrent_hash, torrent_name))
            export_action.triggered.connect(lambda: self.export_torrent(torrent_hash, torrent_name))
            rename_action.triggered.connect(lambda: self.open_rename_torrent_dialog(torrent_hash, torrent_name))
            remove_action.triggered.connect(lambda: self.open_remove_torrent_dialog(torrent_hash, torrent_name))

            context_menu.addAction(copy_hash_action)
            context_menu.addAction(open_action)
            context_menu.addAction(export_action)
            context_menu.addAction(rename_action)
            context_menu.addAction(remove_action)

            context_menu.exec(event.globalPos())
        elif isinstance(item, TorrentListWidgetTorrentHashImportItem):
            torrent_hash = item.torrent_hash
            torrent_name = item.torrent_name

            context_menu = QMenu(self)
            rename_action = QAction(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogNewFolder),
                                    "Rename torrent import", self)
            remove_action = QAction(self.style().standardIcon(QStyle.StandardPixmap.SP_TrashIcon), "Remove torrent import",
                                    self)

            rename_action.triggered.connect(lambda: self.open_rename_torrent_dialog(torrent_hash, torrent_name))
            remove_action.triggered.connect(lambda: self.remove_torrent_hash_import(torrent_hash, torrent_name))

            context_menu.addAction(rename_action)
            context_menu.addAction(remove_action)

            context_menu.exec(event.globalPos())

    def open_torrent_location(self, torrent_hash: str, torrent_name: str):
        io_thread_inbox.put(("ui_open_torrent_location", torrent_hash))

    def export_torrent(self, torrent_hash: str, torrent_name: str):
        TorrentExportDialog(torrent_hash, torrent_name).exec()

    def open_rename_torrent_dialog(self, torrent_hash: str, torrent_name: str):
        TorrentRenameDialog(torrent_hash, torrent_name).exec()

    def open_remove_torrent_dialog(self, torrent_hash: str, torrent_name: str):
        TorrentRemoveDialog(torrent_hash, torrent_name).exec()

    def rename_torrent_hash_import(self, torrent_hash: str, torrent_name: str):
        TorrentHashImportRenameDialog(torrent_hash, torrent_name).exec()

    def remove_torrent_hash_import(self, torrent_hash: str, torrent_name: str):
        TorrentHashImportRemoveDialog(torrent_hash, torrent_name).exec()


class MainWindow(QWidget):
    def __init__(self, port_str: str, appdata_str: str, target_tracker_host: str):
        super().__init__()
        self.init_ui()

        self.io_thread = IoThread(io_thread_inbox, port_str, appdata_str, target_tracker_host)
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
        self.import_torrent_by_hash_button = QPushButton("Import torrent by hash...")
        self.import_torrent_by_hash_button.clicked.connect(self.open_torrent_hash_import_dialog)
        top_buttons_layout.addWidget(self.import_torrent_by_hash_button)
        layout.addLayout(top_buttons_layout)

        self.label = QLabel("Connecting to central tracker...")
        layout.addWidget(self.label)

        # Add the torrent list widget
        self.torrent_list = TorrentListWidget()
        layout.addWidget(self.torrent_list)

        self.setLayout(layout)
        self.resize(640, 480)
        self.setMinimumSize(600, 400)

    def open_torrent_creation_dialog(self):
        TorrentCreationDialog().exec()

    def open_torrent_import_dialog(self):
        TorrentImportDialog().exec()

    def open_torrent_hash_import_dialog(self):
        TorrentHashImportDialog().exec()

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
            _, pending_hash_import_torrents, torrents = message
            self.update_torrent_list(pending_hash_import_torrents, torrents)

    def format_torrent_status(self, piece_states: list[bool], seeder_count: int) -> str:
        total_pieces = len(piece_states)
        completed_pieces = piece_states.count(True)

        if completed_pieces == total_pieces:
            return "Seeding"

        completion_percentage = (completed_pieces / total_pieces) * 100
        if seeder_count > 0:
            return f"Downloading, {completion_percentage:.1f}% ({completed_pieces}/{total_pieces} pcs)"
        else:
            return f"Stalled, {completion_percentage:.1f}% ({completed_pieces}/{total_pieces} pcs)"

    def format_hash_import_status(self, can_be_requested: bool):
        if can_be_requested:
            return "Requesting info...."
        return "Stalled"

    def update_torrent_list(self, torrent_hash_import_states: list[UiTorrentHashImportState], torrent_states: list[UiTorrentState]):
        self.torrent_list.clear()
        for ui_torrent_hash_import_state in torrent_hash_import_states:
            formatted_status = self.format_hash_import_status(ui_torrent_hash_import_state.can_be_requested)
            item_widget = TorrentListWidgetTorrentHashImportWidget(ui_torrent_hash_import_state.torrent_name, formatted_status)

            list_item = TorrentListWidgetTorrentHashImportItem(self.torrent_list, ui_torrent_hash_import_state.sha256_hash, ui_torrent_hash_import_state.torrent_name)
            list_item.setSizeHint(item_widget.sizeHint())
            self.torrent_list.addItem(list_item)
            self.torrent_list.setItemWidget(list_item, item_widget)
        for ui_torrent_state in torrent_states:
            formatted_status = self.format_torrent_status(ui_torrent_state.piece_states, ui_torrent_state.seeder_count)
            item_widget = TorrentListWidgetTorrentWidget(ui_torrent_state.torrent_name, formatted_status)

            list_item = TorrentListWidgetTorrentItem(self.torrent_list, ui_torrent_state.sha256_hash, ui_torrent_state.torrent_name)
            list_item.setSizeHint(item_widget.sizeHint())
            self.torrent_list.addItem(list_item)
            self.torrent_list.setItemWidget(list_item, item_widget)

    def closeEvent(self, event):
        io_thread_inbox.put("ui_quit")
        self.io_thread.wait()
        event.accept()


def main():
    window_title = "HK241/MemoryLeak: TorrentClone (Qt UI)"

    app = QApplication(sys.argv)

    parser = QCommandLineParser()
    port_option = QCommandLineOption("port", "The port that other peers should connect to.", "port", "65433")
    appdata_option = QCommandLineOption("appdata", "App data location.", "appdata", "appdata")
    window_title_suffix_option = QCommandLineOption("window-title-suffix", "Window title suffix.", "suffix")
    target_tracker_host_option = QCommandLineOption("target-tracker-host", "Target tracker IP.", "target", "localhost")
    parser.addOption(port_option)
    parser.addOption(appdata_option)
    parser.addOption(window_title_suffix_option)
    parser.addOption(target_tracker_host_option)
    parser.process(app)

    main_window = MainWindow(parser.value(port_option), parser.value(appdata_option), parser.value(target_tracker_host_option))
    if parser.isSet(window_title_suffix_option):
        window_title = f"{window_title} - {parser.value(window_title_suffix_option)}"
    main_window.setWindowTitle(window_title)
    main_window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
