"""This module contains plugins regarding listing files provided by the node."""

from typing import Sequence

from teatime import Context, Issue, NodeType, PluginException, Severity
from teatime.plugins.base import IPFSRPCPlugin


class CIDFSEnum(IPFSRPCPlugin):
    """Check whether the given CIDs are present on the node.

    Severity: Medium

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-ls
    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-file-ls

    A common IPFS file path is leaking directory contents of UNIX filesystem
    objects. Depending on where IPFS has been mounted, this can leak
    f"confidential information.
    """

    INTRUSIVE = False

    def __init__(self, cid_paths: Sequence[str] = None):
        self.cid_paths = cid_paths or []

    def check_paths(self, context: Context, endpoint: str):
        for ipfs_path in self.cid_paths:
            try:
                payload = self.get_rpc_json(
                    target=context.target, route=endpoint, params={"arg": ipfs_path}
                )
            except PluginException:
                continue

            context.report.add_issue(
                Issue(
                    title="Found an Exposed IPFS Content ID",
                    description=(
                        "A common IPFS file path is leaking directory contents of UNIX filesystem "
                        "objects. Depending on where IPFS has been mounted, this can leak "
                        f"confidential information. Endpoint: {endpoint}"
                    ),
                    severity=Severity.MEDIUM,
                    raw_data=payload,
                )
            )

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        self.check_paths(context=context, endpoint="/api/v0/ls")
        self.check_paths(context=context, endpoint="/api/v0/file/ls")


class UnixFSEnum(IPFSRPCPlugin):
    """Check whether the objects in the local mutable namespace can be listed.

    Severity: Medium

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-files-ls

    The UNIX root directory path is leaking contents of UNIX filesystem
    objects. An attacker can use this endpoint along with the /files/read
    endpoint to enumerate potentially confidential data on the system.
    """

    INTRUSIVE = False

    def __init__(self, path: str = None):
        self.path = path or "/"

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        payload = self.get_rpc_json(
            target=context.target, route="/api/v0/files/ls", params={"arg": self.path}
        )

        context.report.add_issue(
            Issue(
                title="Found an Exposed UNIX Filesystem Root",
                description=(
                    "The UNIX root directory path is leaking contents of UNIX filesystem "
                    "objects. An attacker can use this endpoint along with the /files/read "
                    "endpoint to enumerate potentially confidential data on the system."
                ),
                severity=Severity.MEDIUM,
                raw_data=payload,
            )
        )

        # TODO: Optional attempt to write


class FilestoreEnum(IPFSRPCPlugin):
    """Check whether the objects in the filestore can be listed.

    Severity: Medium

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-filestore-ls

    The filestore endpoint is leaking contents of its objects. An attacker
    can use this endpoint to enumerate potentially confidential data on the
    system.
    """

    INTRUSIVE = False

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        payload = self.get_rpc_json(
            target=context.target,
            route="/api/v0/filestore/ls",
        )

        context.report.add_issue(
            Issue(
                title="Found Exposed Filestore Objects",
                description=(
                    "The filestore endpoint is leaking contents of its objects. An attacker "
                    "can use this endpoint to enumerate potentially confidential data on the "
                    "system."
                ),
                severity=Severity.MEDIUM,
                raw_data=payload,
            )
        )
