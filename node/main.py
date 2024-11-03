from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QFileDialog, QDialog, QHBoxLayout, \
    QLineEdit

import sys
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import json
import struct
import queue

from harbor import Harbor
from peer_data import generate_unique_id, PeerData
from torrent_file import TorrentFile, pack_files_to_pieces

TRACKER_HOST = '127.0.0.1'
TRACKER_PORT = 65432
PEER_HOST = '127.0.0.1'
PEER_PORT = 65433

io_thread_inbox = queue.Queue()

def send_message(harbor: Harbor, sock: socket, message):
    try:
        message_data = json.dumps(message).encode("utf-8")
        packed_data = struct.pack(">I", len(message_data)) + message_data
        sock.sendall(packed_data)
    except Exception as e:
        print(f"Error sending data to {sock.getpeername()}: {e}")
        harbor.socket_receiver_queue_remove_client_command(sock)

class IoThread(QThread):
    ui_thread_inbox_ready = pyqtSignal(object)

    def run(self):
        my_peer_id = generate_unique_id()
        print(f"I/O thread: ID is {my_peer_id}")

        executor = ThreadPoolExecutor(max_workers=5)

        peers: dict[socket.socket, PeerData] = {}

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((PEER_HOST, PEER_PORT))
        server_socket.listen()
        print(f"I/O thread: listening on {PEER_HOST}:{PEER_PORT} for other peers...")

        harbor = Harbor(server_socket, io_thread_inbox)
        harbor.start()

        tracker_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tracker_sock.connect((TRACKER_HOST, TRACKER_PORT))
        print(f"I/O thread: connected to tracker {TRACKER_HOST}:{TRACKER_PORT}. Adding to Harbor.")
        harbor.socket_receiver_queue_add_client_command(tracker_sock)

        self.ui_thread_inbox_ready.emit(("string_message", "hi"))

        stop_requested = False
        keep_running = True
        while keep_running:
            try:
                message = io_thread_inbox.get(timeout=0.1)
                message_type = message[0]
                if message_type == "harbor_connection_added":
                    _, sock, peer_name = message
                    if sock == tracker_sock:
                        print(f"I/O thread: connected to tracker {peer_name[0]}:{peer_name[1]}. Sending ID.")
                        executor.submit(send_message, harbor, sock, ("peer_id", my_peer_id))
                    else:
                        print(f"I/O thread: connected to peer {peer_name[0]}:{peer_name[1]}.")
                elif message_type == "harbor_connection_removed":
                    _, sock, peer_name, caused_by_stop = message
                    if sock == tracker_sock:
                        if caused_by_stop:
                            print(f"I/O thread: disconnected from tracker {peer_name[0]}:{peer_name[1]}.")
                        else:
                            print(f"I/O thread: disconnected from tracker {peer_name[0]}:{peer_name[1]}! Stopping.")
                            stop_requested = True
                elif message_type == "harbor_message":
                    _, sock, peer_name, msg = message
                    if sock == tracker_sock:
                        msg_command_type = msg[0]
                        if msg_command_type == "motd":
                            _, motd = msg
                            print(f"I/O thread: MOTD from tracker {peer_name[0]}:{peer_name[1]}: `{motd}`")
                        else:
                            print(f"I/O thread: message from tracker {peer_name[0]}:{peer_name[1]}: {msg}")
                    else:
                        print(f"I/O thread: message from peer {peer_name[0]}:{peer_name[1]}: {msg}")
                elif message == "harbor_stopped":
                    print(f"I/O thread: Harbor stopped.")
                    keep_running = False
                elif message == "ui_quit":
                    stop_requested = True
                else:
                    print(f"I/O thread: I/O message: {message}")
            except queue.Empty:
                continue
            except KeyboardInterrupt:
                stop_requested = True

            if stop_requested:
                stop_requested = False
                print("I/O thread: stopping Harbor...")
                harbor.stop()

        executor.shutdown()
        print("I/O thread: bye")

def quit_io_thread():
    io_thread_inbox.put("ui_quit")

class TorrentCreationDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.file_button = QPushButton("Select file")
        self.file_button.clicked.connect(self.select_file)
        layout.addWidget(self.file_button)

        self.folder_button = QPushButton("Select folder")
        self.folder_button.clicked.connect(self.select_folder)
        layout.addWidget(self.folder_button)

        self.setLayout(layout)
        self.setWindowTitle("Torrent Creation")
        self.setGeometry(400, 400, 250, 100)

    def select_file(self):
        options = QFileDialog.Option.ReadOnly
        file_path, _ = QFileDialog.getOpenFileName(self, "Select a file", "", "All Files (*)", options=options)
        if file_path:
            io_thread_inbox.put(("create_torrent", file_path))

    def select_folder(self):
        """Open a folder dialog to select a folder."""
        folder_path = QFileDialog.getExistingDirectory(self, "Select a folder", "")
        if folder_path:
            io_thread_inbox.put(("create_torrent", folder_path))

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

        # Start the I/O thread
        self.io_thread = IoThread()
        self.io_thread.ui_thread_inbox_ready.connect(self.on_message_received)
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

    # def send_message(self):
    #     io_thread_inbox.put("hi")
    #     self.label.setText("Message sent to I/O thread.")

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