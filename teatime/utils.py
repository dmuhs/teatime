"""This module contains various utility functions around scanning."""

import socket
from contextlib import closing


def check_port(host: str, port: int, timeout: int = 2):
    """Check whether a given port is available on the target host.

    .. todo:: Add details!

    :param timeout:
    :param host:
    :param port:
    :return:
    """
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0
