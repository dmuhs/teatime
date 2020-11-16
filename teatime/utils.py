"""This module contains various utility functions around scanning."""
import json
import socket
from contextlib import closing
from typing import List

import requests
from requests.exceptions import ConnectTimeout, ReadTimeout

from teatime.plugins import PluginException


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


# TODO: Make base JSONRPCPlugin method
def decode_rpc_int(target, method, params: List[str] = None, idx: int = 1) -> int:
    """Attempt to make an RPC call and decode the result as an integer.

    :param target: The RPC target URL
    :param method: The RPC method
    :param params: Additional RPC method params (optional)
    :param idx: RPC call index (optional)
    :return: The payload result as integer
    :raises PluginException: If connection or payload-related errors occur
    """
    params = params or []
    try:
        rpc_response = requests.post(
            target,
            json={"jsonrpc": "2.0", "method": method, "params": params, "id": idx},
        )
    except (ConnectTimeout, ConnectionError, ReadTimeout) as e:
        raise PluginException(f"Connection Error: {e}")

    try:
        payload = rpc_response.json()
    except json.JSONDecodeError:
        raise PluginException(f"Could not decode response {rpc_response.text}")
    try:
        return int(payload["result"], 16)
    except ValueError:
        raise PluginException(f"Could not decode payload result {payload}")


def reverse_dns(address: str) -> str:
    """Attempt to resolve an IP address to its DNS name.

    :param address: The IP address to resolve
    :return: The IP's DNS name as a string
    """
    try:
        result = socket.gethostbyaddr(address)[0]
    except socket.herror:
        result = address
    return result
