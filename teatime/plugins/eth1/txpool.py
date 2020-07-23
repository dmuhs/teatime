"""This module contains checks regarding a node's transaction pool."""

from teatime.plugins import Context, NodeType, Plugin
from teatime.reporting import Issue, Severity


class TxPoolContent(Plugin):
    def _check(self, context: Context) -> None:
        """Try to fetch the transaction pool contents.

        .. todo:: Add details!

        :param context:
        """
        if context.node_type == NodeType.GETH:
            payload = self.get_rpc_json(
                context.target, method="txpool_content", params=[]
            )
            context.report.add_issue(
                Issue(
                    title="TxPool Content",
                    description="Anyone can see the transcation pool contents using the txpool_content RPC call.",
                    raw_data=payload,
                    severity=Severity.LOW,
                )
            )
        elif context.node_type == NodeType.PARITY:
            payload = self.get_rpc_json(
                context.target, method="parity_pendingTransactions", params=[]
            )
            context.report.add_issue(
                Issue(
                    title="TxPool Content",
                    description="Anyone can see the transaction pool contents using the parity_pendingTransactions RPC "
                    "call.",
                    raw_data=payload,
                    severity=Severity.LOW,
                )
            )


class GethTxPoolInspection(Plugin):
    def _check(self, context: Context) -> None:
        """Try to inspect the transaction pool.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(context.target, method="txpool_inspect", params=[])
        context.report.add_issue(
            Issue(
                title="TxPool Inspection",
                description="Anyone can inspect the transaction pool using the txpool_inspect RPC call.",
                raw_data=payload,
                severity=Severity.LOW,
            )
        )


class GethTxPoolStatus(Plugin):
    def _check(self, context: Context) -> None:
        """Try to fetch the transaction pool status.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(context.target, method="txpool_status", params=[])
        context.report.add_issue(
            Issue(
                title="TxPool Status",
                description="Anyone can see the transaction pool status using the txpool_status RPC call.",
                raw_data=payload,
                severity=Severity.LOW,
            )
        )


class ParityTxPoolStatistics(Plugin):
    def _check(self, context: Context) -> None:
        """Try to fetch the transaction pool statistics.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(
            context.target, method="parity_pendingTransactionsStats", params=[]
        )
        context.report.add_issue(
            Issue(
                title="TxPool Statistics",
                description="Anyone can see the transaction pool statistics using the parity_pendingTransactionsStats "
                "RPC call.",
                raw_data=payload,
                severity=Severity.LOW,
            )
        )
