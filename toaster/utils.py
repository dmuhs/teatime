"""This module contains various utility functions around scanning."""

import socket
from contextlib import closing


def check_port(host, port):
    """Check whether a given port is available on the target host.

    .. todo:: Add details!

    :param host:
    :param port:
    :return:
    """
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(2)
        return sock.connect_ex((host, port)) == 0
