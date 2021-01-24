"""This module contains a plugin to test a node's remote shutdown functionality."""

from teatime import Context, Issue, NodeType, Severity
from teatime.plugins.base import IPFSRPCPlugin


class Shutdown(IPFSRPCPlugin):
    """Attempt to list all active P2P listeners.

    Severity: Critical

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-shutdown

    Anyone can shut down the IPFS daemon. This plugin has shut down the node.
    This is the highest possible threat to availability. Why would you leave
    this enabled? Are you insane?
    """

    INTRUSIVE = True  # damn right it is

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        payload = self.get_rpc_json(
            target=context.target, route="/api/v0/shutdown", raw=True
        )
        context.report.add_issue(
            Issue(
                title="Exposed Shutdown Endpoint",
                description=(
                    "Anyone can shut down the IPFS daemon. This plugin has shut down the node. "
                    "This is the highest possible threat to availability."
                ),
                severity=Severity.CRITICAL,
                raw_data=payload,
            )
        )
