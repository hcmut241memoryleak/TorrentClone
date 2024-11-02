from socket import *

serverName = 'localhost'
serverPort = 12000

def main():
    print("Client: Hi")

    client_socket = socket(AF_INET, SOCK_DGRAM)
    while True:
        message = input('Client: Input lowercase sentence: ')
        if message == "exit":
            break
        client_socket.sendto(message.encode(), (serverName, serverPort))
        modified_message, server_address = client_socket.recvfrom(2048)
        print(modified_message.decode())
    client_socket.close()

if __name__ == "__main__":
    main()