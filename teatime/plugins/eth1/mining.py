"""This module contains a plugin for mining-related checks."""

from teatime.plugins import Context, JSONRPCPlugin
from teatime.reporting import Issue, Severity


class MiningStatus(JSONRPCPlugin):
    """Check whether the node is mining.

    Severity: Medium

    This plugin will use the :code:`eth_mining` method to find out whether
    a node is mining or not. If there is a difference to the user-specified
    value, an issue will be logged.
    """

    INTRUSIVE = False

    def __init__(self, should_mine: bool):
        self.should_mine = should_mine

    def _check(self, context: Context) -> None:
        mining_status = self.get_rpc_json(context.target, "eth_mining")

        if self.should_mine is not None and mining_status != self.should_mine:
            context.report.add_issue(
                Issue(
                    title="Mining Status",
                    description=(
                        "The node should be mining but isn't"
                        if self.should_mine
                        else "The node should not be mining but is"
                    ),
                    raw_data=mining_status,
                    severity=Severity.MEDIUM,
                )
            )


class HashrateStatus(JSONRPCPlugin):
    """Check whether the node has a certain hash rate.

    Severity: Medium

    This plugin will use the :code:`eth_hashrate` method to fetch the
    node's hash rate. If the hash rate is different from a user-specified
    value, an issue will be logged.
    """

    INTRUSIVE = False

    def __init__(self, expected_hashrate: int):
        self.expected_hashrate = expected_hashrate

    def _check(self, context: Context) -> None:
        current_hashrate = int(self.get_rpc_json(context.target, "eth_hashrate"), 16)

        if current_hashrate < self.expected_hashrate:
            context.report.add_issue(
                Issue(
                    title="Mining Hashrate Low",
                    description=(
                        f"The hashrate should be >= {self.expected_hashrate} "
                        f"but only is {current_hashrate}"
                    ),
                    raw_data=current_hashrate,
                    severity=Severity.MEDIUM,
                )
            )
