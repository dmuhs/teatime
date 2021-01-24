"""This module contains plugins regarding listing and manipulating a node's pins."""

from teatime import Context, Issue, NodeType, Severity
from teatime.plugins.base import IPFSRPCPlugin


class AddPin(IPFSRPCPlugin):
    """Detect where it's possible to add new pin.

    Severity: High

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-pin-add

    Open pinning can enable an attacker to flush a large amount of
    random data onto the node's disk until storage space is exhausted,
    thus performing a denial of service attack against future uploads/pins.
    """

    INTRUSIVE = True

    def __init__(self, cid: str = "Qmf9vKuR6MnTEGYXhzwpMib5EFGoXPWCJh3mXTvasb3Cas"):
        self.cid = cid  # file named "teatime" without content

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        payload = self.get_rpc_json(
            target=context.target, route="/api/v0/pin/add", params={"arg": self.cid}
        )

        context.report.add_issue(
            Issue(
                title="Anyone can pin data to the node",
                description=(
                    "Open pinning can enable an attacker to flush a large amount of"
                    "random data onto the node's disk until storage space is exhausted,"
                    "thus performing a denial of service attack against future uploads/pins."
                ),
                raw_data=payload,
                severity=Severity.HIGH,
            )
        )


class EnumeratePins(IPFSRPCPlugin):
    """Detect where it's possible to list the node's pins.

    Severity: Low

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-pin-ls

    It is possible to list all the content IDs that are pinned to the node's local storage.
    """

    INTRUSIVE = False

    def __init__(self, cid: str = "Qmf9vKuR6MnTEGYXhzwpMib5EFGoXPWCJh3mXTvasb3Cas"):
        self.cid = cid  # file named "teatime" without content

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        payload = self.get_rpc_json(
            target=context.target,
            route="/api/v0/pin/ls",
        )

        context.report.add_issue(
            Issue(
                title="Anyone can list the node's pins",
                description=(
                    "It is possible to list all the content IDs that "
                    "are pinned to the node's local storage."
                ),
                raw_data=payload,
                severity=Severity.LOW,
            )
        )


class RemovePin(IPFSRPCPlugin):
    """Detect where it's possible to remove the node's pins.

    Severity: High

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-pin-rm

    It is possible to remove all the content IDs that
    are pinned to the node's local storage. This poses
    a risk to data availability as an attacker can unpin
    any file.
    """

    INTRUSIVE = True

    def __init__(
        self,
        pin: str = "Qmf9vKuR6MnTEGYXhzwpMib5EFGoXPWCJh3mXTvasb3Cas",
        restore: bool = True,
    ):
        self.pin = pin
        self.restore = restore

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        payload = self.get_rpc_json(
            target=context.target, route="/api/v0/pin/rm", params={"arg": self.pin}
        )

        context.report.add_issue(
            Issue(
                title="Anyone can remove the node's pins",
                description=(
                    "It is possible to remove all the content IDs that "
                    "are pinned to the node's local storage. This poses "
                    "a risk to data availability as an attacker can unpin "
                    "any file."
                ),
                raw_data=payload,
                severity=Severity.HIGH,
            )
        )

        if self.restore:
            # Attempt to restore the deleted pin
            # TODO: log message if restoration succeeded/failed
            self.get_rpc_json(
                target=context.target, route="/api/v0/pin/add", params={"arg": self.pin}
            )


# TODO: Test whether pins can be updated
