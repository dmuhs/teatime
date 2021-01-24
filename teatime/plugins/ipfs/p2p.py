"""This module contains plugins regarding leaked P2P network information"""

from teatime import Context, Issue, NodeType, Severity
from teatime.plugins.base import IPFSRPCPlugin


class P2PListListeners(IPFSRPCPlugin):
    """Attempt to list all active P2P listeners.

    Severity: Low

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-p2p-ls

    Anyone is able to list the P2P listener services running on this node.
    This method may leak internal information on other peer-to-peer services
    running on this node.
    """

    INTRUSIVE = False

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        payload = self.get_rpc_json(
            target=context.target,
            route="/api/v0/p2p/ls",
        )
        context.report.add_issue(
            Issue(
                title="Exposed P2P Listener List",
                description=(
                    "Anyone is able to list the P2P listener services running on this node. "
                    "This method may leak internal information on other peer-to-peer services "
                    "running on this node."
                ),
                severity=Severity.LOW,
                raw_data=payload,
            )
        )


class P2PListStreams(IPFSRPCPlugin):
    """Attempt to list all active P2P streams.

    Severity: Low

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-p2p-stream-ls

    Anyone is able to list the active P2P streams on this node.
    This method may leak internal information on other peer-to-peer services
    and connections on this node.
    """

    INTRUSIVE = False

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        payload = self.get_rpc_json(
            target=context.target,
            route="/api/v0/p2p/stream/ls",
        )
        context.report.add_issue(
            Issue(
                title="Exposed P2P Stream List",
                description=(
                    "Anyone is able to list the active P2P streams on this node. "
                    "This method may leak internal information on other peer-to-peer services "
                    "and connections on this node."
                ),
                severity=Severity.LOW,
                raw_data=payload,
            )
        )


class P2PCloseStream(IPFSRPCPlugin):
    """Attempt to close all active P2P streams.

    Severity: High

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-p2p-stream-close

    Anyone is able to close active P2P streams on this node.
    This exposed functionality may be used by an attacker to
    disrupt the node's availability and block connections.
    """

    INTRUSIVE = True

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        payload = self.get_rpc_json(
            target=context.target,
            route="/api/v0/p2p/stream/close",
            params={"all": True},
            raw=True,
        )
        context.report.add_issue(
            Issue(
                title="Exposed P2P Stream Management endpoint",
                description=(
                    "Anyone is able to close active P2P streams on this node. "
                    "This exposed functionality may be used by an attacker to "
                    "disrupt the node's availability and block connections."
                ),
                severity=Severity.HIGH,
                raw_data=payload,
            )
        )


class P2PStopForwarding(IPFSRPCPlugin):
    """Attempt to stop the node from listening to new connection forwards.

    Severity: High

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-p2p-close

    Anyone is able to close active P2P forwardings on this node.
    This exposed functionality may be used by an attacker to
    disrupt the node's availability and block connections.
    """

    INTRUSIVE = True

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        payload = self.get_rpc_json(
            target=context.target,
            route="/api/v0/p2p/close",
            params={"all": True},
            raw=True,
        )
        context.report.add_issue(
            Issue(
                title="Exposed P2P Management endpoint",
                description=(
                    "Anyone is able to close active P2P forwardings on this node. "
                    "This exposed functionality may be used by an attacker to "
                    "disrupt the node's availability and block connections."
                ),
                severity=Severity.HIGH,
                raw_data=payload,
            )
        )


class P2PEnableForwarding(IPFSRPCPlugin):
    """Attempt to enable forwarding new connections to the libp2p service.

    Severity: High

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-p2p-forward

    Anyone is able to register P2P forwardings on this node.
    This exposed functionality may be used by an attacker to
    disrupt the node's availability and block connections.
    """

    INTRUSIVE = True

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        # TODO: validate that this doesn't trigger an internal server error
        payload = self.get_rpc_json(
            target=context.target,
            route="/api/v0/p2p/forward",
            params=[("arg", "/x/"), ("arg", "127.0.0.1"), ("arg", "127.0.0.1")],
            raw=True,
        )
        context.report.add_issue(
            Issue(
                title="Exposed P2P Management endpoint",
                description=(
                    "Anyone is able to register P2P forwardings on this node. "
                    "This exposed functionality may be used by an attacker to "
                    "disrupt the node's availability and block connections."
                ),
                severity=Severity.HIGH,
                raw_data=payload,
            )
        )


class P2PCreateListener(IPFSRPCPlugin):
    """Attempt to enable forwarding new connections to the libp2p service.

    Severity: High

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-p2p-listen

    Anyone is able to register P2P listeners on this node.
    This exposed functionality may be used by an attacker to
    disrupt the node's availability and block connections.
    """

    INTRUSIVE = True

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        # TODO: validate that this doesn't trigger an internal server error
        payload = self.get_rpc_json(
            target=context.target,
            route="/api/v0/p2p/listen",
            params=[("arg", "/teatime/"), ("arg", "127.0.0.1")],
            raw=True,
        )
        context.report.add_issue(
            Issue(
                title="Exposed P2P Management endpoint",
                description=(
                    "Anyone is able to register P2P listeners on this node. "
                    "This exposed functionality may be used by an attacker to "
                    "disrupt the node's availability and block connections."
                ),
                severity=Severity.HIGH,
                raw_data=payload,
            )
        )
