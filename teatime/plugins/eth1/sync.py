"""This module contains a plugin checking for node sync issues."""

import requests

from teatime.plugins import Context, Plugin
from teatime.reporting import Issue, Severity


class NodeSync(Plugin):
    """A plugin to check for issues in node synchronization."""

    def __init__(self, infura_url):
        self.infura_url = infura_url

    def _check(self, context: Context) -> None:
        """Check the node's sync state and whether it's stuck.

        .. todo:: Add details!

        :param context:
        """
        node_syncing = self.get_rpc_json(context.target, "eth_syncing")
        node_blocknum = int(self.get_rpc_json(context.target, "eth_blockNumber"), 16)
        net_blocknum = self.get_latest_block_number()
        block_threshold = 10

        if node_blocknum < (net_blocknum - block_threshold) and not node_syncing:
            context.report.add_issue(
                Issue(
                    title="Synchronization Status",
                    description="The node's block number is stale and its not synchronizing. The node is stuck!",
                    raw_data=node_syncing,
                    severity=Severity.CRITICAL,
                )
            )
        else:
            # TODO: More info if node is syncing? E.g. how many blocks to go
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

        .. todo:: Add details!

        :return:
        """
        rpc_response = requests.post(
            self.infura_url,
            json={"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1},
        )
        # TODO: Better error handling
        return int(rpc_response.json()["result"], 16)
