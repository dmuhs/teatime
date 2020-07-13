"""This module contains a plugin for network-related checks."""

from toaster.plugins import Context, NodeType, Plugin
from toaster.reporting import Issue, Severity


# TODO: Whisper (shh) checks for parity?
class NetworkMethodCheck(Plugin):
    """This plugin contains network-related checks."""

    name = "RPC Network Information"
    version = "0.1.3"
    node_type = (NodeType.GETH, NodeType.PARITY)

    # custom settings
    minimum_peercount: int

    def __repr__(self):
        return f"<NetworkMethodCheck v{self.version}>"

    def check_listening(self, context):
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

    def check_peercount(self, context):
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

    def run(self, context: Context):
        """Check for network-related vulnerabilities and weaknesses.

        .. todo:: Add details!

        :param context:
        """
        self.run_catch("Node listening", self.check_listening, context)
        self.run_catch("Peer count", self.check_peercount, context)

        context.report.add_meta(self.name, self.version)
