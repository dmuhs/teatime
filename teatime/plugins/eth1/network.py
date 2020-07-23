"""This module contains a plugin for network-related checks."""

from teatime.plugins import Context, Plugin, NodeType
from teatime.reporting import Issue, Severity


# TODO: Whisper (shh) checks for parity?


class NetworkListening(Plugin):
    def _check(self, context: Context) -> None:
        """Check whether the node is listening for peers.

        .. todo:: Add details!

        :param context:
        """
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


class PeerCountStatus(Plugin):
    def __init__(self, minimum_peercount: int):
        self.minimum_peercount = minimum_peercount

    def _check(self, context: Context) -> None:
        """Check whether the node has a certain peer count.

        .. todo:: Add details!

        :param context:
        """
        current_peercount = self.get_rpc_json(context.target, "net_peerCount")

        if self.minimum_peercount is not None and self.minimum_peercount > int(
            current_peercount, 16
        ):
            context.report.add_issue(
                Issue(
                    title="Number of peers too low!",
                    description=f"Too few peers (current < minimum): {current_peercount} < {self.minimum_peercount}",
                    raw_data=current_peercount,
                    severity=Severity.MEDIUM,
                )
            )


class PeerlistManipulation(Plugin):
    def __init__(self, test_enode: str):
        self.test_enode = test_enode

    def _check(self, context: Context) -> None:
        """Try to add a peer to the node's peer list.

        .. todo:: Add details!

        :param context:
        """
        if context.node_type == NodeType.GETH:
            payload = self.get_rpc_json(
                context.target, method="admin_addPeer", params=[self.test_enode]
            )
            context.report.add_issue(
                Issue(
                    title="Peer list manipulation",
                    description="Arbitrary peers can be added using the admin_addPeer RPC call.",
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
            context.report.add_issue(
                Issue(
                    title="Peer list manipulation",
                    description="Reserved peers can be added to the node's peer list using the parity_addReservedPeer RPC "
                    "call",
                    raw_data=payload,
                    severity=Severity.HIGH,
                )
            )


class ParityDropPeers(Plugin):
    def _check(self, context: Context) -> None:
        """Try to remove non-reserved peers from the peer list.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(
            context.target, method="parity_dropNonReservedPeers"
        )
        if payload:
            context.report.add_issue(
                Issue(
                    title="Peer list manipulation",
                    description="Anyone can drop the non-reserved peerlist on the node using the "
                    "parity_dropNonReservedPeers RPC call.",
                    raw_data=payload,
                    severity=Severity.CRITICAL,
                )
            )
