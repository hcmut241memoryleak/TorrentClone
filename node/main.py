from socket import *
import json
import struct

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432

def main():
    print("Client: Hi")

    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))
    while True:
        try:
            raw_msg_len = sock.recv(4)
            if not raw_msg_len:
                break
            msg_len = struct.unpack('>I', raw_msg_len)[0]

            data = b""
            while len(data) < msg_len:
                packet = sock.recv(msg_len - len(data))
                if not packet:
                    break
                data += packet

            json_data = json.loads(data.decode('utf-8'))
            print(f"Received from server: {json_data}")

        except Exception as e:
            print(f"Error receiving message: {e}")
            break
    sock.close()

if __name__ == "__main__":
    main()