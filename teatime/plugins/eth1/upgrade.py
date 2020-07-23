from teatime.plugins import Context, NodeType, Plugin
from teatime.reporting import Issue, Severity


class ParityUpgrade(Plugin):
    def _check(self, context: Context) -> None:
        """Try to check for an available upgrade.

        .. todo:: Add details!

        :param context:
        """
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(context.target, method="parity_upgradeReady")
        context.report.add_issue(
            Issue(
                title="The node can be upgraded",
                description="Anyone can upgrade the node using the parity_upgradeReady RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )
