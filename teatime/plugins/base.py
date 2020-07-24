"""This module holds the base plugin class and exception."""

import abc
from typing import List, Union

import requests
from loguru import logger
from requests.exceptions import ConnectionError, ConnectTimeout, ReadTimeout

from .context import Context


class PluginException(Exception):
    """An exception for plugin-related errors."""

    pass


class Plugin(abc.ABC):
    """The base plugin class."""

    INTRUSIVE: bool = True

    def __repr__(self):
        return f"<Plugin[{self.__class__.__name__}]>"

    @staticmethod
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
        try:
            resp = requests.post(
                target,
                json={
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": params or [],
                    "id": idx,
                },
                timeout=3,
                # verify=False,
                headers={"User-Agent": "This is for research purposes, I promise!"},
            )
        except (ConnectTimeout, ConnectionError, ReadTimeout) as e:
            raise PluginException(f"Connection Error: {e}")

        if resp.status_code != 200:
            raise PluginException(f"RPC call returned with status {resp.status_code}")

        payload = resp.json()
        payload_error = payload.get("error")
        if payload_error is not None:
            raise PluginException(payload_error.get("message"))

        if payload.get("result") is None:
            raise PluginException(f"Received empty result in RPC response in {payload}")

        return payload["result"]

    @abc.abstractmethod
    def _check(self, context: Context):
        pass

    def run(self, context: Context):
        """The plugin's entrypoint as invoked by the scanner.

        This method will call the plugin's :code:`_check` method, which should
        be overridden by concrete Plugin instances. It will catch any
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
