"""This module holds the base plugin class and exception."""

import abc
import json
from functools import wraps
from json import JSONDecodeError
from typing import List, Optional, Sequence, Union

import requests
from loguru import logger
from requests.exceptions import ConnectionError, ConnectTimeout, ReadTimeout

from .context import Context


def handle_connection_errors(func):
    """Catch connection-related excetions and reraise.

    This slim wrapper will catch connection and decoding errors, and requests-related exceptions to
    reraise them as PluginErrors so we can catch them in a standardized way.
    """

    @wraps(func)
    def handle(*args, **kwargs):
        try:
            resp = func(*args, **kwargs)
        except (ConnectTimeout, ConnectionError, ReadTimeout, JSONDecodeError) as e:
            raise PluginException(f"Connection Error: {e}")
        return resp

    return handle


class PluginException(Exception):
    """An exception for plugin-related errors."""

    pass


class BasePlugin(abc.ABC):
    """The base plugin class."""

    INTRUSIVE: bool = True

    def __repr__(self):
        return f"<JSONRPCPlugin[{self.__class__.__name__}]>"

    @abc.abstractmethod
    def _check(self, context: Context):
        pass  # pragma: no cover

    def run(self, context: Context):
        """The plugin's entrypoint as invoked by the scanner.

        This method will call the plugin's :code:`_check` method, which should
        be overridden by concrete JSONRPCPlugin instances. It will catch any
        :code:`PluginException` and skip the execution. In any case, at the end
        of the check run, the plugin name is added as a meta field to denote
        that it has been executed.

        :param context: The context object containing report-related information
        """
        scan_name = self.__class__.__name__

        logger.info(f"Running scan: {scan_name}")
        try:
            self._check(context)
        except PluginException as e:
            logger.info(f"{scan_name}: Terminated with exception {e}")

        context.report.add_meta(scan_name, True)


class JSONRPCPlugin(BasePlugin, abc.ABC):
    """A base plugin for JSON-RPC APIs."""

    @staticmethod
    @handle_connection_errors
    def get_rpc_json(
        target: str, method: str, params: List[Union[str, int]] = None, idx: int = 0
    ):
        """Execute an RPC call against a given target.

        The current timeout for the RPC request is three seconds. Any :code:`PluginException`
        instances raised, contain the reason in the message string, e.g. if a connection
        failure occurred, the response status code was not 200, an error field is present, or
        if the result field is left empty.

        :param target: The target URI to send the request to
        :param method: The RPC method to use
        :param params: Additional parameters for the method (optional)
        :param idx: The RPC call's ID (optional)
        :return: The response payload's "result" field
        :raises PluginException: If the request faied or the response is inconsistent
        """

        resp = requests.post(
            target,
            json={
                "jsonrpc": "2.0",
                "method": method,
                "params": params or [],
                "id": idx,
            },
            timeout=3,
            headers={"User-Agent": "This is for research purposes, I promise!"},
        )

        if resp.status_code != 200:
            raise PluginException(f"RPC call returned with status {resp.status_code}")

        payload = resp.json()
        payload_error = payload.get("error")
        if payload_error is not None:
            raise PluginException(payload_error.get("message"))

        if payload.get("result") is None:
            raise PluginException(f"Received empty result in RPC response in {payload}")

        return payload["result"]

    @staticmethod
    @handle_connection_errors
    def get_rpc_int(target, method, params: List[str] = None, idx: int = 1) -> int:
        """Attempt to make an RPC call and decode the result as an integer.

        :param target: The RPC target URL
        :param method: The RPC method
        :param params: Additional RPC method params (optional)
        :param idx: RPC call index (optional)
        :return: The payload result as integer
        :raises PluginException: If connection or payload-related errors occur
        """
        params = params or []
        payload = requests.post(
            target,
            json={"jsonrpc": "2.0", "method": method, "params": params, "id": idx},
        ).json()

        try:
            return int(payload["result"], 16)
        except ValueError:
            raise PluginException(f"Could not decode payload result {payload}")


class IPFSRPCPlugin(BasePlugin, abc.ABC):
    @staticmethod
    @handle_connection_errors
    def get_rpc_json(
        target: str,
        route: str = "",
        params: Union[dict, Sequence[tuple]] = None,
        headers: Optional[dict] = None,
        files: Optional[dict] = None,
        raw: bool = False,
        timeout: int = 3,
        stream_limit: int = None,
    ):
        """Send a  request to the IPFS HTTP API.

        :param target: The target to send the request to
        :param route: The URL to send the API request to
        :param params: A dict of URL parameters to add
        :param headers: Optional headers to attach
        :param files: A dictionary of files to upload
        :param raw: If true, the result will not interpreted as JSON
        :param timeout: Number of seconds to wait until timing out
        :param stream_limit: Maximum number of lines to read
        :return:
        """
        files = files
        params = params or {}
        headers = headers or {}
        request_headers = {"User-Agent": "This is for research purposes, I promise!"}
        request_headers.update(headers)

        if stream_limit is None:
            resp = requests.post(
                url=target + route,
                params=params,
                timeout=timeout,
                headers=request_headers,
                files=files,
            )
            content = resp.text
        else:
            resp = requests.post(
                url=target + route,
                params=params,
                timeout=timeout,
                headers=request_headers,
                files=files,
                stream=True,
            )

            content = ""
            for i, chunk in enumerate(resp.iter_lines(decode_unicode=True)):
                if i >= stream_limit:
                    break
                content += chunk + "\n"

        if resp.status_code != 200:
            raise PluginException(f"RPC call returned with status {resp.status_code}")

        if raw or stream_limit:
            return content
        else:
            return json.loads(content)
