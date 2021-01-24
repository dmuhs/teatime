"""This module contains plugins with admin interface checks."""

from teatime.plugins import Context, JSONRPCPlugin, NodeType
from teatime.reporting import Issue, Severity


class GethDatadir(JSONRPCPlugin):
    """Try to fetch Geth's data directory.

    Severity: Low

    Geth: https://geth.ethereum.org/docs/rpc/ns-admin#admin_datadir
    """

    INTRUSIVE = False

    def _check(self, context: Context):
        if context.node_type != NodeType.GETH:
            return

        payload = self.get_rpc_json(context.target, method="admin_datadir")
        context.report.add_issue(
            Issue(
                title="Admin datadir access",
                description=(
                    "The datadir directory path can be fetched "
                    "using the admin_datadir RPC call."
                ),
                raw_data=payload,
                severity=Severity.LOW,
            )
        )


class GethNodeInfo(JSONRPCPlugin):
    """Try to fetch admin info about the node.

    Severity: Low

    Geth: https://geth.ethereum.org/docs/rpc/ns-admin#admin_nodeinfo
    """

    INTRUSIVE = False

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.GETH:
            return

        payload = self.get_rpc_json(context.target, method="admin_nodeInfo")
        context.report.add_issue(
            Issue(
                title="Admin Node Info Leaks",
                description=(
                    "Admin-only information can be fetched using "
                    "the admin_nodeInfo RPC call."
                ),
                raw_data=payload,
                severity=Severity.LOW,
            )
        )


class ParityDevLogs(JSONRPCPlugin):
    """Try to fetch the node's developer logs.

    Severity: Critical

    Parity/OpenEthereum: https://openethereum.github.io/wiki/JSONRPC-parity-module#parity_devlogs
    """

    INTRUSIVE = False

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(context.target, method="parity_devLogs")
        context.report.add_issue(
            Issue(
                title="Developer log information leak",
                description=(
                    "The node's developer logs can be fetched "
                    "using the parity_devLogs RPC call."
                ),
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )


class PeerlistLeak(JSONRPCPlugin):
    """Try to fetch peer list information.

    Severity: Medium

    Geth: https://geth.ethereum.org/docs/rpc/ns-admin#admin_peers
    Parity/OpenEthereum: https://openethereum.github.io/wiki/JSONRPC-parity-module#parity_netpeers
    """

    INTRUSIVE = False

    def _check(self, context: Context) -> None:
        if context.node_type == NodeType.PARITY:
            payload = self.get_rpc_json(context.target, method="parity_netPeers")
            context.report.add_issue(
                Issue(
                    title="Peer list information leak",
                    description=(
                        "Admin-only peer list information can be fetched "
                        "with the parity_netPeers RPC call."
                    ),
                    raw_data=payload,
                    severity=Severity.MEDIUM,
                )
            )
        elif context.node_type == NodeType.GETH:
            payload = self.get_rpc_json(context.target, method="admin_peers")
            context.report.add_issue(
                Issue(
                    title="Admin Peerlist Access",
                    description=(
                        "Admin-only information about the peer list can be "
                        "fetched using the admin_peers RPC call."
                    ),
                    raw_data=payload,
                    severity=Severity.MEDIUM,
                )
            )
