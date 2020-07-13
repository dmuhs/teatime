"""This module holds the base plugin class and exception.

.. todo::

    Explain base class functionality

"""

import abc

import requests
from loguru import logger
from requests.exceptions import ConnectionError, ConnectTimeout, ReadTimeout


class PluginException(Exception):
    """An exception for RPC-related errors.

    .. todo:: Add details!
    """
    pass


class Plugin(abc.ABC):
    """The base plugin class.

    .. todo:: Add details!
    """
    name = None
    version = None
    node_type = None

    @abc.abstractmethod
    def run(self, context):
        """The plugin's entrypoint as invoked by the scanner.

        .. todo:: Add details!

        :param context:
        """
        pass

    @classmethod
    def setup(cls, config=None):
        """Set up the plugin.

        This classmethod takes a configuration dict and sets each
        key-value pair as class-level attributes, returning the
        class with all attributes set.

        :param config:
        :return:
        """
        for key, value in config.items():
            setattr(cls, key, value)
        return cls

    @staticmethod
    def run_catch(check_name, check_func, context):
        """Run a function and catch any PluginExceptions.

        .. todo:: Add details!

        :param check_name:
        :param check_func:
        :param context:
        """
        logger.info(f"Running scan: {check_name}")
        try:
            check_func(context)
        except PluginException as e:
            logger.info(f"{check_name}: Terminated with exception {e}")

    @staticmethod
    def get_rpc_json(target, method, params=None, idx=0):
        """Execute an RPC call against a given target.

        .. todo:: Add details!

        :param target:
        :param method:
        :param params:
        :param idx:
        :return:
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

        # TODO: More explicit RPC exception for better catches
        if resp.status_code != 200:
            raise PluginException(f"RPC call returned with status {resp.status_code}")

        payload = resp.json()
        payload_error = payload.get("error")
        if payload_error is not None:
            raise PluginException(payload_error.get("message"))

        if payload.get("result") is None:
            raise PluginException(f"Received empty result in RPC response in {payload}")

        return payload["result"]
