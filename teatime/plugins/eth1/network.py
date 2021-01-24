"""This module contains a plugin for network-related checks."""

from teatime.plugins import Context, JSONRPCPlugin, NodeType
from teatime.reporting import Issue, Severity


class NetworkListening(JSONRPCPlugin):
    """Check whether the node is listening for peers.

    Severity: High

    This plugin will use the :code:`net_listening` method to check
    whether the node is listening to new peers. If that is not the
    case, an issue will be logged.
    """

    INTRUSIVE = False

    def _check(self, context: Context) -> None:
        node_listening = self.get_rpc_json(context.target, "net_listening")

        # SCAN[HIGH]: Node not listening to peers
        if not node_listening:
            context.report.add_issue(
                Issue(
                    title="Node not listening to peers",
                    description="The node is not listening to new peer requests",
                    raw_data=node_listening,
                    severity=Severity.HIGH,
                )
            )


class PeerCountStatus(JSONRPCPlugin):
    """Check whether the node has a certain peer count.

    Severity: Medium

    This plugin will use the :code:`net_peerCount` method to check the
    node's peer count. If the value is lower than the user-specified
    value of minimum peers, an issue will be logged.
    """

    INTRUSIVE = False

    def __init__(self, minimum_peercount: int):
        self.minimum_peercount = minimum_peercount

    def _check(self, context: Context) -> None:
        current_peercount = int(self.get_rpc_json(context.target, "net_peerCount"), 16)

        if self.minimum_peercount > current_peercount:
            context.report.add_issue(
                Issue(
                    title="Number of peers too low!",
                    description=(
                        f"Too few peers (current < minimum): "
                        f"{current_peercount} < {self.minimum_peercount}"
                    ),
                    raw_data=current_peercount,
                    severity=Severity.MEDIUM,
                )
            )


class PeerlistManipulation(JSONRPCPlugin):
    """Try to add a peer to the node's peer list.

    Severity: High

    This plugin will attempt to add a given peer to the node's peer
    list.
    """

    INTRUSIVE = True

    def __init__(self, test_enode: str):
        self.test_enode = test_enode

    def _check(self, context: Context) -> None:
        if context.node_type == NodeType.GETH:
            payload = self.get_rpc_json(
                context.target, method="admin_addPeer", params=[self.test_enode]
            )
            if payload:
                context.report.add_issue(
                    Issue(
                        title="Peer list manipulation",
                        description=(
                            "Arbitrary peers can be added using "
                            "the admin_addPeer RPC call."
                        ),
                        raw_data=payload,
                        severity=Severity.HIGH,
                    )
                )
        elif context.node_type == NodeType.PARITY:
            payload = self.get_rpc_json(
                context.target,
                method="parity_addReservedPeer",
                params=[self.test_enode],
            )
            if payload:
                context.report.add_issue(
                    Issue(
                        title="Peer list manipulation",
                        description=(
                            "Reserved peers can be added to the node's "
                            "peer list using the parity_addReservedPeer RPC call"
                        ),
                        raw_data=payload,
                        severity=Severity.HIGH,
                    )
                )


class ParityDropPeers(JSONRPCPlugin):
    """Try to remove non-reserved peers from the peer list.

    Severity: Critical

    This plugin will attempt to drop all non-reserved peer entries
    from the node's peer table.
    """

    INTRUSIVE = True

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(
            context.target, method="parity_dropNonReservedPeers"
        )
        if payload:
            context.report.add_issue(
                Issue(
                    title="Peer list manipulation",
                    description=(
                        "Anyone can drop the non-reserved peerlist on the "
                        "node using the parity_dropNonReservedPeers RPC call."
                    ),
                    raw_data=payload,
                    severity=Severity.CRITICAL,
                )
            )
