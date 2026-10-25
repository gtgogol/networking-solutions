import socket
import threading


HOST, PORT = "127.0.0.1", 8000

def tcp_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
        #tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_socket.bind((HOST, PORT))
        tcp_socket.listen()
        print("TCP запущен")

        while True:
            connection, address = tcp_socket.accept()
            with connection:
                data = connection.recv(4096)
                if data:
                    print("TCP:", address, data.hex())


def udp_server():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        #udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_socket.bind((HOST, PORT))
        print("UDP запущен")

        while True:
            data, address = udp_socket.recvfrom(4096)
            print("UDP:", address, data.hex())

def tcp_handler():
    pass

def udp_handler():
    pass

 

if __name__ == "__main__":
    threading.Thread(target=tcp_server, daemon=True).start()
    threading.Thread(target=udp_server, daemon=True).start()

    threading.Event().wait()