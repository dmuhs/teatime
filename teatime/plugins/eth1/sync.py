"""This module contains a plugin checking for node sync issues."""

import json

import requests
from plugins import PluginException
from requests import ConnectTimeout, ReadTimeout

from teatime.plugins import Context, Plugin
from teatime.reporting import Issue, Severity


class NodeSync(Plugin):
    """Check the node's sync state and whether it's stuck.

    Severity: None/Critical

    This plugin fetches the sync state if the node. If it is not syncing,
    the most recent block number is fetched from Infura using the :code:`eth_blockNumber`
    method. If the most recent block number is higher than the node's block number
    with a certain threshold, the node might be stuck and out of sync with the mainnet.
    In that case, a critical issue is logged. Otherwise, an informational issue
    on the current sync state is logged.
    """

    def __init__(self, infura_url, block_threshold: int = 10):
        self.infura_url = infura_url
        self.block_threshold = block_threshold

    def _check(self, context: Context) -> None:
        node_syncing = self.get_rpc_json(context.target, "eth_syncing")
        node_blocknum = int(self.get_rpc_json(context.target, "eth_blockNumber"), 16)
        net_blocknum = self.get_latest_block_number()

        if node_blocknum < (net_blocknum - self.block_threshold) and not node_syncing:
            context.report.add_issue(
                Issue(
                    title="Synchronization Status",
                    description="The node's block number is stale and its not synchronizing. The node is stuck!",
                    raw_data=node_syncing,
                    severity=Severity.CRITICAL,
                )
            )
        else:
            context.report.add_issue(
                Issue(
                    title="Synchronization Status",
                    description=f"Syncing: {node_syncing} Block Number: {node_blocknum}",
                    raw_data=node_syncing,
                    severity=Severity.NONE,
                )
            )

    def get_latest_block_number(self) -> int:
        """Fetch the latest block number.

        This method fetches the latest block number using the :code:`eth_blockNumber`
        from the user-specified Infura API URL.

        :return: The current block number as an integer
        """
        try:
            rpc_response = requests.post(
                self.infura_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_blockNumber",
                    "params": [],
                    "id": 1,
                },
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
