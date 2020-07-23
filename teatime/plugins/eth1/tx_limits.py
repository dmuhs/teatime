from teatime.plugins import Context, NodeType, Plugin
from teatime.reporting import Issue, Severity


class ParityTxCeiling(Plugin):
    def _check(self, context: Context) -> None:
        """Try to set the maximum transaction gas.

        .. todo:: Add details!

        :param context:
        """
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(
            context.target, method="parity_setMaxTransactionGas", params=["0x186a0"]
        )
        context.report.add_issue(
            Issue(
                title="Transaction maximum gas can be changed",
                description="Anyone can change the maximum transaction gas limit using the "
                "parity_setMaxTransactionGas RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )


class ParityTxFloor(Plugin):
    def _check(self, context: Context) -> None:
        """Try to set the minimum transaction gas limit.

        .. todo:: Add details!

        :param context:
        """
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(
            context.target, method="parity_setMinGasPrice", params=["0x0"]
        )
        context.report.add_issue(
            Issue(
                title="Transaction minimum gas can be changed",
                description="Anyone can change the minimum transaction gas limit using the parity_setMinGasPrice RPC "
                "call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )
