import socket
import socks
import time

# socks5 server ip and port
socks.setdefaultproxy(socks.SOCKS5, "192.168.158.151", 8888, username="admin", password="123456")
socket.socket = socks.socksocket

def udp_echo_client(server_ip, server_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        for i in range(50000):
            message = f'Hello, UDP server! Message #{i+1}'
            
            print(f"Sending: {message}")
            sock.sendto(message.encode(), (server_ip, server_port))

            data, _ = sock.recvfrom(1024)  # buffer size is 1024 bytes
            print(f"Received echo: {data.decode()}")
        

    finally:
        sock.close()

# ncat -u -l 0.0.0.0 1234 --keep-open --exec "/bin/cat"
if __name__ == "__main__":
    server_ip = "192.168.158.151"  # server ip
    server_port = 1234       # server port
    udp_echo_client(server_ip, server_port)
