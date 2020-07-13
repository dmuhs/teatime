"""This module contains a plugin for mining-related checks."""

from toaster.plugins import Context, Plugin
from toaster.reporting import Issue, Severity


class MiningNodeDetector(Plugin):
    """A plugin for mining-related checks."""

    name = "RPC Mining Check"
    version = "0.1.3"

    # custom settings
    should_mine: bool
    expected_hashrate: int

    def __repr__(self):
        return f"<MiningNodeDetector v{self.version}>"

    def check_mining(self, context: Context) -> None:
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

    def check_hashrate(self, context: Context) -> None:
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

    def run(self, context: Context) -> None:
        """Check for mining-related weaknesses and misconfigurations.

        .. todo:: Add details!

        :param context:
        """
        # SCAN[MEDIUM]: Illegal mining state
        self.run_catch("Mining status", self.check_mining, context)
        # SCAN[MEDIUM]: Hashrate too low
        self.run_catch("Hashrate status", self.check_hashrate, context)

        context.report.add_meta(self.name, self.version)
