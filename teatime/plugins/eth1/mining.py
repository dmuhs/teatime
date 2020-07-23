"""This module contains a plugin for mining-related checks."""

from teatime.plugins import Context, Plugin
from teatime.reporting import Issue, Severity


class MiningStatus(Plugin):
    def __init__(self, should_mine: bool):
        self.should_mine = should_mine

    def _check(self, context: Context) -> None:
        """Check whether the node is mining.

        .. todo:: Add details!

        :param context:
        """
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


class HashrateStatus(Plugin):
    def __init__(self, expected_hashrate: int):
        self.expected_hashrate = expected_hashrate

    def check_(self, context: Context) -> None:
        """Check whether the node has a certain hash rate.

        .. todo:: Add details!

        :param context:
        """
        current_hashrate = self.get_rpc_json(context.target, "eth_hashrate")
        expected_hashrate = context.extra.get("expected_hashrate")

        if expected_hashrate is not None and current_hashrate < expected_hashrate:
            context.report.add_issue(
                Issue(
                    title="Mining Hashrate Low",
                    description=f"The hashrate should be >= {expected_hashrate} but only is {current_hashrate}",
                    raw_data=current_hashrate,
                    severity=Severity.MEDIUM,
                )
            )
