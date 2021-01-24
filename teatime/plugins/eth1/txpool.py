"""This module contains checks regarding a node's transaction pool."""

from teatime.plugins import Context, JSONRPCPlugin, NodeType
from teatime.reporting import Issue, Severity


class TxPoolContent(JSONRPCPlugin):
    """Try to fetch the transaction pool contents.

    Severity: Low

    Parity/OpenEthereum:
    https://openethereum.github.io/wiki/JSONRPC-parity-module#parity_pendingtransactions
    Geth:
    https://geth.ethereum.org/docs/rpc/ns-txpool#txpool_content
    """

    INTRUSIVE = False

    def _check(self, context: Context) -> None:
        if context.node_type == NodeType.GETH:
            payload = self.get_rpc_json(context.target, method="txpool_content")
            context.report.add_issue(
                Issue(
                    title="TxPool Content",
                    description=(
                        "Anyone can see the transcation pool contents "
                        "using the txpool_content RPC call."
                    ),
                    raw_data=payload,
                    severity=Severity.LOW,
                )
            )
        elif context.node_type == NodeType.PARITY:
            payload = self.get_rpc_json(
                context.target, method="parity_pendingTransactions"
            )
            context.report.add_issue(
                Issue(
                    title="TxPool Content",
                    description=(
                        "Anyone can see the transaction pool contents "
                        "using the parity_pendingTransactions RPC call."
                    ),
                    raw_data=payload,
                    severity=Severity.LOW,
                )
            )


class GethTxPoolInspection(JSONRPCPlugin):
    """Try to inspect the transaction pool.

    Severity: Low

    Geth: https://geth.ethereum.org/docs/rpc/ns-txpool#txpool_inspect
    """

    INTRUSIVE = False

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.GETH:
            return
        payload = self.get_rpc_json(context.target, method="txpool_inspect")
        context.report.add_issue(
            Issue(
                title="TxPool Inspection",
                description=(
                    "Anyone can inspect the transaction pool "
                    "using the txpool_inspect RPC call."
                ),
                raw_data=payload,
                severity=Severity.LOW,
            )
        )


class GethTxPoolStatus(JSONRPCPlugin):
    """Try to fetch the transaction pool status.

    Severity: Low

    Geth: https://geth.ethereum.org/docs/rpc/ns-txpool#txpool_status
    """

    INTRUSIVE = False

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.GETH:
            return
        payload = self.get_rpc_json(context.target, method="txpool_status")
        context.report.add_issue(
            Issue(
                title="TxPool Status",
                description=(
                    "Anyone can see the transaction pool status "
                    "using the txpool_status RPC call."
                ),
                raw_data=payload,
                severity=Severity.LOW,
            )
        )


class ParityTxPoolStatistics(JSONRPCPlugin):
    """Try to fetch the transaction pool statistics.

    Severity: Low

    Parity:
    https://openethereum.github.io/wiki/JSONRPC-parity-module#parity_pendingtransactionsstats
    """

    INTRUSIVE = False

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.PARITY:
            return
        payload = self.get_rpc_json(
            context.target, method="parity_pendingTransactionsStats"
        )
        context.report.add_issue(
            Issue(
                title="TxPool Statistics",
                description=(
                    "Anyone can see the transaction pool statistics "
                    "using the parity_pendingTransactionsStats RPC call."
                ),
                raw_data=payload,
                severity=Severity.LOW,
            )
        )
