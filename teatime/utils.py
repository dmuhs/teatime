"""This module contains various utility functions around scanning."""

import socket
from contextlib import closing


def check_port(host: str, port: int, timeout: int = 2) -> bool:
    """Check whether a given port is available on the target host.

    This helper function will attempt to connect to a given port on the
    target host.

    :param timeout: Number of seconds to time out after
    :param host: The target host to connect to
    :param port: The target port to connect to
    :return: A boolean indicating whether the connection was successful
    """
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0
