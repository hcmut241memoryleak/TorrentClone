import socket
import time

import select
import threading
from concurrent.futures import ThreadPoolExecutor
import json
import struct
import queue

from enum import Enum

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432
MAX_CONNECTIONS = 16

class MainThreadMessageType(Enum):
    CONNECTION_ADDED = "connection_added"
    CONNECTION_REMOVED = "connection_removed"

main_thread_inbox = queue.Queue()

connections = {}
connections_lock = threading.Lock()
socket_receiver_daemon_inbox = queue.Queue()
socket_receiver_daemon_signal_r, socket_receiver_daemon_signal_w = socket.socketpair()

daemons_stop_event = threading.Event()

def handle_incoming_data(sock):
    try:
        raw_msg_len = sock.recv(4)
        if not raw_msg_len:
            return False
        msg_len = struct.unpack(">I", raw_msg_len)[0]

        data = b""
        while len(data) < msg_len:
            packet = sock.recv(msg_len - len(data))
            if not packet:
                return False
            data += packet

        json_data = json.loads(data.decode("utf-8"))
        main_thread_inbox.put(("message", sock, json_data))
        return True

    except Exception as e:
        print(f"Receiver thread: error handling data from {sock.getpeername()}: {e}. Will disconnect.")
        socket_receiver_queue_remove_client_command(sock)
        return False

def socket_receiver_queue_add_client_command(sock):
    socket_receiver_daemon_inbox.put(("+", sock))
    socket_receiver_daemon_signal_w.send(b"\x01")

def socket_receiver_queue_remove_client_command(sock):
    socket_receiver_daemon_inbox.put(("-", sock))
    socket_receiver_daemon_signal_w.send(b"\x01")

def socket_receiver_daemon():
    while not daemons_stop_event.is_set():
        with connections_lock:
            monitored_sockets = [socket_receiver_daemon_signal_r] + list(connections.keys())

        readable_socks, _, _ = select.select(monitored_sockets, [], [], 1)  # Adding a timeout for select
        for selected_sock in readable_socks:
            if selected_sock is socket_receiver_daemon_signal_r:
                socket_receiver_daemon_signal_r.recv(1)
                while not socket_receiver_daemon_inbox.empty():
                    command, command_sock = socket_receiver_daemon_inbox.get()
                    with connections_lock:
                        if command == "+":
                            connections[command_sock] = command_sock.getpeername()
                            main_thread_inbox.put((MainThreadMessageType.CONNECTION_ADDED, command_sock))
                        elif command == "-":
                            if command_sock in connections:
                                peer_name = command_sock.getpeername()
                                del connections[command_sock]
                                try:
                                    command_sock.close()
                                except Exception as e:
                                    print(f"Error closing connection to {peer_name}: {e}. Will disregard.")
                                    return False
                                main_thread_inbox.put((MainThreadMessageType.CONNECTION_REMOVED, command_sock, peer_name))
                break
            else:
                handle_incoming_data(selected_sock)

def socket_acceptor_daemon(server_socket: socket):
    server_socket.setblocking(False)
    while not daemons_stop_event.is_set():
        try:
            client_socket, client_address = server_socket.accept()
            client_socket.settimeout(5)
            socket_receiver_queue_add_client_command(client_socket)
        except socket.error as e:
            if daemons_stop_event.is_set():
                break
            time.sleep(0.1)
        except Exception as e:
            print(f"Acceptor thread: unexpected error: {e}")
            time.sleep(0.1)

def send_message(sock, message):
    try:
        message_data = json.dumps(message).encode("utf-8")
        packed_data = struct.pack(">I", len(message_data)) + message_data
        sock.sendall(packed_data)
    except Exception as e:
        print(f"Error sending data to {sock.getpeername()}: {e}")
        socket_receiver_queue_remove_client_command(sock)

def main():
    executor = ThreadPoolExecutor(max_workers=5)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(MAX_CONNECTIONS)
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}...")

    sock_recv_thread = threading.Thread(target=socket_receiver_daemon, daemon=True)
    sock_accp_thread = threading.Thread(target=socket_acceptor_daemon, daemon=True, args=[server_socket])

    sock_recv_thread.start()
    sock_accp_thread.start()

    try:
        while True:
            try:
                message = main_thread_inbox.get(timeout=0.1)
                message_type = message[0]
                if message_type == MainThreadMessageType.CONNECTION_ADDED:
                    _, sock = message
                    print(f"Main thread: connected from {sock.getpeername()}.")

                    executor.submit(send_message, sock, "Hello from server")
                elif message_type == MainThreadMessageType.CONNECTION_REMOVED:
                    _, sock, peer_name = message
                    print(f"Main thread: connection to {peer_name} removed.")
            except queue.Empty:
                continue
    except KeyboardInterrupt:
        print("Shutting down server...")
        daemons_stop_event.set()
        socket_receiver_daemon_signal_w.send(b'\x01')
        sock_recv_thread.join()
        sock_accp_thread.join()
        print("Server shut down successfully.")

if __name__ == "__main__":
    main()