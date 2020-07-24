"""This module contains plugins around setting transaction-related limits."""
from teatime.plugins import Context, NodeType, Plugin
from teatime.reporting import Issue, Severity


class ParityTxCeiling(Plugin):
    """Try to set the maximum transaction gas.

    Severity: Critical

    Parity/OpenEthereum: https://openethereum.github.io/wiki/JSONRPC-parity_set-module#parity_setmaxtransactiongas
    """

    def _check(self, context: Context) -> None:
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


class ParityMinGasPrice(Plugin):
    """Try to set the minimum transaction gas price.

    Severity: Critical

    Parity/OpenEthereum: https://openethereum.github.io/wiki/JSONRPC-parity_set-module#parity_setmingasprice
    """

    def _check(self, context: Context) -> None:
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
