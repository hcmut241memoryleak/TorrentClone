import socket
import time
import select
import threading
import json
import struct
import queue

class Harbor:
    def __init__(self, server_socket, main_thread_inbox: queue.Queue):
        self.__server_socket = server_socket
        self.__main_thread_inbox = main_thread_inbox
        self.__connections = {}
        self.__connections_lock = threading.Lock()
        self.__socket_receiver_daemon_inbox = queue.Queue()
        self.__socket_receiver_daemon_signal_r, self.__socket_receiver_daemon_signal_w = socket.socketpair()
        self.__daemons_stop_event = threading.Event()
        
        self.__sock_recv_thread = None
        self.__sock_accp_thread = None

    def __handle_incoming_data(self, sock):
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
            self.__main_thread_inbox.put(("harbor_message", sock, json_data))
            return True

        except Exception as e:
            print(f"Harbor @ receiver thread: error handling data from {sock.getpeername()}: `{e}`. Will disconnect.")
            self.socket_receiver_queue_remove_client_command(sock)
            return False

    def socket_receiver_queue_add_client_command(self, sock):
        self.__socket_receiver_daemon_inbox.put(("+", sock))
        self.__socket_receiver_daemon_signal_w.send(b"\x01")

    def socket_receiver_queue_remove_client_command(self, sock):
        self.__socket_receiver_daemon_inbox.put(("-", sock))
        self.__socket_receiver_daemon_signal_w.send(b"\x01")

    def __socket_receiver_daemon(self):
        while not self.__daemons_stop_event.is_set():
            with self.__connections_lock:
                monitored_sockets = [self.__socket_receiver_daemon_signal_r] + list(self.__connections.keys())

            readable_socks, _, _ = select.select(monitored_sockets, [], [], 1)  # Adding a timeout for select
            for selected_sock in readable_socks:
                if selected_sock is self.__socket_receiver_daemon_signal_r:
                    self.__socket_receiver_daemon_signal_r.recv(1)
                    while not self.__socket_receiver_daemon_inbox.empty():
                        command, command_sock = self.__socket_receiver_daemon_inbox.get()
                        with self.__connections_lock:
                            if command == "+":
                                self.__connections[command_sock] = command_sock.getpeername()
                                self.__main_thread_inbox.put(("harbor_connection_added", command_sock))
                            elif command == "-":
                                if command_sock in self.__connections:
                                    peer_name = command_sock.getpeername()
                                    del self.__connections[command_sock]
                                    try:
                                        command_sock.close()
                                    except Exception as e:
                                        print(f"Harbor @ receiver thread: error closing connection to {peer_name}: `{e}`. Will disregard.")
                                        return False
                                    self.__main_thread_inbox.put(("harbor_connection_removed", command_sock, peer_name))
                    break
                else:
                    self.__handle_incoming_data(selected_sock)

    def __socket_acceptor_daemon(self):
        self.__server_socket.setblocking(False)
        while not self.__daemons_stop_event.is_set():
            try:
                client_socket, client_address = self.__server_socket.accept()
                client_socket.settimeout(5)
                self.socket_receiver_queue_add_client_command(client_socket)
            except socket.error as e:
                if self.__daemons_stop_event.is_set():
                    break
                time.sleep(0.1)
            except Exception as e:
                print(f"Harbor @ acceptor thread: unexpected error: `{e}`")
                time.sleep(0.1)

    def start(self):
        self.__sock_recv_thread = threading.Thread(target=self.__socket_receiver_daemon, daemon=True)
        self.__sock_accp_thread = threading.Thread(target=self.__socket_acceptor_daemon, daemon=True)

        self.__sock_recv_thread.start()
        self.__sock_accp_thread.start()

    def stop(self):
        self.__daemons_stop_event.set()
        self.__socket_receiver_daemon_signal_w.send(b'\x01')
        self.__sock_recv_thread.join()
        self.__sock_accp_thread.join()