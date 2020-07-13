"""This module contains checks regarding a node's transaction pool."""

from toaster.plugins import Context, NodeType, Plugin
from toaster.reporting import Issue, Severity


class GethTxPoolCheck(Plugin):
    """A plugin to check for Geth-related tx pool issues."""

    name = "Geth Transaction Pool Information"
    version = "0.4.0"
    node_type = (NodeType.GETH,)

    def check_txpool_content(self, context):
        """Try to fetch the transaction pool contents.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(context.target, method="txpool_content", params=[])
        context.report.add_issue(
            Issue(
                title="TxPool Content",
                description="Anyone can see the transcation pool contents using the txpool_content RPC call.",
                raw_data=payload,
                severity=Severity.LOW,
            )
        )

    def check_txpool_inspection(self, context):
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

    def check_txpool_status(self, context):
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

    def run(self, context):
        """Run the Geth-related transaction pool checks.

        .. todo:: Add details!

        :param context:
        :return:
        """
        if context.node_type != NodeType.GETH:
            return
        # SCAN[LOW]: GETH Tx pool content leak
        self.run_catch("Geth txpool content", self.check_txpool_content, context)
        # SCAN[LOW]: GETH Tx pool inspection leak
        self.run_catch("Geth txpool inspect", self.check_txpool_inspection, context)
        # SCAN[LOW]: GETH Tx pool status leak
        self.run_catch("Geth txpool status", self.check_txpool_status, context)
        context.report.add_meta(self.name, self.version)


class ParityTxPoolCheck(Plugin):
    """A plugin to check for Parity/OpenEthereum-related transaction pool issues."""

    name = "RPC Transaction Pool Information"
    version = "0.4.0"
    node_type = (NodeType.PARITY,)

    def check_txpool_stats(self, context):
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

    def check_txpool_content(self, context):
        """Try to fetch the transaction pool contents.

        .. todo:: Add details!

        :param context:
        """
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

    def run(self, context):
        """Run the Parity/OpenEthereum-related transaction pool checks.

        .. todo:: Add details!

        :param context:
        :return:
        """
        if context.node_type != NodeType.PARITY:
            return
        # SCAN[LOW]: PARITY Tx pool stats leak
        self.run_catch("Parity txpool statistics", self.check_txpool_stats, context)
        # SCAN[LOW]: PARITY Tx pool content leak
        self.run_catch("Parity txpool content", self.check_txpool_content, context)
        context.report.add_meta(self.name, self.version)


class TxPoolCheck(Plugin):
    """A plugin to execute Geth- and Parity/OpenEthereum-related tx pool checks."""
    name = "RPC Transaction Pool Information"
    version = "0.5.0"
    node_type = (NodeType.GETH, NodeType.PARITY)

    def __repr__(self):
        return f"<TxPoolCheck v{self.version}>"

    def run(self, context: Context):
        """Run Geth- or Parity/OpenEthereum-related tx pool checks.

        .. todo:: Add details!

        :param context:
        :return:
        """
        if context.node_type == NodeType.GETH:
            plugin = GethTxPoolCheck()
        elif context.node_type == NodeType.PARITY:
            plugin = ParityTxPoolCheck()
        else:
            return
        plugin.run(context)
