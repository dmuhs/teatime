"""This module holds the base plugin class and exception."""

import abc
from functools import wraps
from json import JSONDecodeError
from typing import List, Optional, Union

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


class IPFSRPCPlugin(BasePlugin, abc.ABC):
    @staticmethod
    @handle_connection_errors
    def get_rpc_json(
        target: str,
        route: str = "",
        params: dict = None,
        headers: Optional[dict] = None,
        files: Optional[dict] = None,
        raw: bool = False,
    ):
        """
        TODO: write this
        """
        files = files
        params = params or {}
        headers = headers or {}
        request_headers = {"User-Agent": "This is for research purposes, I promise!"}
        request_headers.update(headers)

        resp = requests.post(
            url=target + route,
            params=params,
            timeout=3,
            headers=request_headers,
            files=files,
        )
        if resp.status_code != 200:
            raise PluginException(f"RPC call returned with status {resp.status_code}")

        if raw:
            return resp.text
        else:
            return resp.json()
