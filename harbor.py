import json
import queue
import socket
import struct
import threading

import select


class HarborSocketState:
    is_receiving_message: bool
    current_message_length: int
    current_message_buffer: bytes

    def __init__(self):
        self.is_receiving_message = False
        self.current_message_length = 0
        self.current_message_buffer = b""


class Harbor:
    __server_socket: socket.socket
    __io_thread_inbox: queue.Queue
    __connections: dict[socket, HarborSocketState]
    __connections_lock: threading.Lock
    __socket_receiver_daemon_inbox: queue.Queue
    __socket_receiver_daemon_signal_r: socket.socket
    __socket_receiver_daemon_signal_w: socket.socket
    __daemons_stop_event: threading.Event
    __sock_recv_thread: threading.Thread | None

    def __init__(self, server_socket: socket.socket, io_thread_inbox: queue.Queue):
        self.__server_socket = server_socket
        self.__io_thread_inbox = io_thread_inbox
        self.__connections = dict()
        self.__connections_lock = threading.Lock()
        self.__socket_receiver_daemon_inbox = queue.Queue()
        self.__socket_receiver_daemon_signal_r, self.__socket_receiver_daemon_signal_w = socket.socketpair()
        self.__daemons_stop_event = threading.Event()
        self.__sock_recv_thread = None

    def __handle_incoming_data(self, sock):
        peer_name = sock.getpeername()
        try:
            state = self.__connections[sock]
            if state.is_receiving_message:
                input_bytes = sock.recv(state.current_message_length - len(state.current_message_buffer))
                if not input_bytes:
                    return False
                state.current_message_buffer += input_bytes
                if len(state.current_message_buffer) >= state.current_message_length:
                    json_data = json.loads(state.current_message_buffer.decode("utf-8"))
                    self.__io_thread_inbox.put(("harbor_message", sock, peer_name, json_data))

                    state.is_receiving_message = False
                    state.current_message_buffer = b""

                return True
            else:
                input_bytes = sock.recv(4 - len(state.current_message_buffer))
                if not input_bytes:
                    return False
                state.current_message_buffer += input_bytes
                if len(state.current_message_buffer) >= 4:
                    state.current_message_length = struct.unpack(">I", state.current_message_buffer)[0]

                    state.is_receiving_message = True
                    state.current_message_buffer = b""

                return True

        except Exception as e:
            print(f"Harbor @ receiver thread: error handling data from {sock.getpeername()}: `{e}`.")
            return False

    def socket_receiver_queue_add_client_command(self, sock):
        self.__socket_receiver_daemon_inbox.put(("+", sock))
        self.__socket_receiver_daemon_signal_w.send(b"\x01")

    def socket_receiver_queue_remove_client_command(self, sock):
        self.__socket_receiver_daemon_inbox.put(("-", sock))
        self.__socket_receiver_daemon_signal_w.send(b"\x01")

    def socket_receiver_queue_stop_command(self):
        self.__socket_receiver_daemon_inbox.put("x")
        self.__socket_receiver_daemon_signal_w.send(b"\x01")

    def __socket_receiver_daemon(self):
        while not self.__daemons_stop_event.is_set():
            with self.__connections_lock:
                monitored_sockets = [self.__socket_receiver_daemon_signal_r, self.__server_socket] + list(self.__connections.keys())

            readable_socks, _, _ = select.select(monitored_sockets, [], [], 1)  # Adding a timeout for select
            for selected_sock in readable_socks:
                if selected_sock is self.__server_socket:
                    client_socket, client_address = self.__server_socket.accept()
                    client_socket.settimeout(10)
                    peer_name = client_socket.getpeername()
                    self.__connections[client_socket] = HarborSocketState()
                    self.__io_thread_inbox.put(("harbor_connection_added", client_socket, peer_name))
                elif selected_sock is self.__socket_receiver_daemon_signal_r:
                    self.__socket_receiver_daemon_signal_r.recv(1)
                    while not self.__socket_receiver_daemon_inbox.empty():
                        command = self.__socket_receiver_daemon_inbox.get()
                        command_type = command[0]
                        with self.__connections_lock:
                            if command_type == "+":
                                command_sock = command[1]
                                peer_name = command_sock.getpeername()
                                self.__connections[command_sock] = HarborSocketState()
                                self.__io_thread_inbox.put(("harbor_connection_added", command_sock, peer_name))
                            elif command_type == "-":
                                command_sock = command[1]
                                if command_sock in self.__connections:
                                    peer_name = command_sock.getpeername()
                                    del self.__connections[command_sock]
                                    try:
                                        command_sock.close()
                                    except Exception as e:
                                        print(
                                            f"Harbor @ receiver thread: error closing connection to {peer_name}: `{e}`. Will disregard.")
                                    self.__io_thread_inbox.put(
                                        ("harbor_connection_removed", command_sock, peer_name, False))
                            elif command_type == "x":
                                for sock in self.__connections.keys():
                                    peer_name = sock.getpeername()
                                    try:
                                        sock.close()
                                    except Exception as e:
                                        print(
                                            f"Harbor @ receiver thread: error closing connection to {peer_name}: `{e}`. Will disregard.")
                                    self.__io_thread_inbox.put(("harbor_connection_removed", sock, peer_name, True))
                                self.__connections.clear()
                                self.__io_thread_inbox.put("harbor_stopped")
                    break
                else:
                    if not self.__handle_incoming_data(selected_sock):
                        self.socket_receiver_queue_remove_client_command(selected_sock)

    def start(self):
        self.__sock_recv_thread = threading.Thread(target=self.__socket_receiver_daemon, daemon=True)
        self.__sock_recv_thread.start()

    def stop(self):
        self.socket_receiver_queue_stop_command()
        self.__daemons_stop_event.set()
        self.__socket_receiver_daemon_signal_w.send(b'\x01')

        self.__sock_recv_thread.join()

        self.__socket_receiver_daemon_signal_r.close()
        self.__socket_receiver_daemon_signal_w.close()