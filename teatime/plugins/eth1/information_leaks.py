"""This module contains plugins with admin interface checks."""

from teatime.plugins import Context, NodeType, Plugin
from teatime.reporting import Issue, Severity


class GethDatadir(Plugin):
    """Check access to the data dir on the Geth admin interface."""

    def _check(self, context: Context):
        """Try to fetch Geth's data directory.

        .. todo:: Add details!

        :param context:
        """
        if context.node_type != NodeType.GETH:
            return

        payload = self.get_rpc_json(context.target, method="admin_datadir", params=[])
        context.report.add_issue(
            Issue(
                title="Admin datadir access",
                description="The datadir directory path can be fetched using the admin_datadir RPC call.",
                raw_data=payload,
                severity=Severity.LOW,
            )
        )


class GethNodeInfo(Plugin):
    def _check(self, context: Context) -> None:
        """Try to fetch admin info about the node.

        .. todo:: Add details!

        :param context:
        """
        if context.node_type != NodeType.GETH:
            return

        payload = self.get_rpc_json(context.target, method="admin_nodeInfo", params=[])
        context.report.add_issue(
            Issue(
                title="Admin Node Info Leaks",
                description="Admin-only information can be fetched using the admin_nodeInfo RPC call.",
                raw_data=payload,
                severity=Severity.LOW,
            )
        )


class ParityDevLogs(Plugin):
    def _check(self, context: Context) -> None:
        """Try to fetch the node's developer logs.

        .. todo:: Add details!

        :param context:
        """
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(context.target, method="parity_devLogs", params=[])
        context.report.add_issue(
            Issue(
                title="Developer log information leak",
                description="The node's developer logs can be fetched using the parity_devLogs RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )


class PeerlistLeak(Plugin):
    def _check(self, context: Context) -> None:
        """Try to fetch peer list information.

        .. todo:: Add details!

        :param context:
        """
        if context.node_type == NodeType.PARITY:
            payload = self.get_rpc_json(
                context.target, method="parity_netPeers", params=[]
            )
            context.report.add_issue(
                Issue(
                    title="Peer list information leak",
                    description="Admin-only peer list information can be fetched with the parity_netPeers RPC call.",
                    raw_data=payload,
                    severity=Severity.CRITICAL,
                )
            )
        elif context.node_type == NodeType.GETH:
            payload = self.get_rpc_json(context.target, method="admin_peers", params=[])
            context.report.add_issue(
                Issue(
                    title="Admin Peerlist Access",
                    description="Admin-only information about the peer list can be fetched using the admin_peers RPC call.",
                    raw_data=payload,
                    severity=Severity.MEDIUM,
                )
            )
