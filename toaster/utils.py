import socket
from contextlib import closing


def check_port(host, port):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(2)
        return sock.connect_ex((host, port)) == 0
