"""This module contains plugins regarding listing and extracting keys."""

from teatime import Context, Issue, NodeType, PluginException, Severity
from teatime.plugins.base import IPFSRPCPlugin


class KeyLeaks(IPFSRPCPlugin):
    """List and attempt to export the node's keys.

    Severity: CRITICAL

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-key-export

    The version endpoint reveals the Go version IPFS has been compiled with,
    along with repository and system information, which may contain sensitive
    data.
    """

    INTRUSIVE = False

    def __init__(self, export: bool = False):
        self.export = export

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        key_list = self.get_rpc_json(target=context.target, route="/api/v0/key/list")

        context.report.add_issue(
            Issue(
                title="Key List Information Leak",
                description=(
                    "Anyone is able to list the keys registered on the node. The name of "
                    "a key can leak information as well and is required for other actions "
                    "such as exporting the key contents."
                ),
                severity=Severity.MEDIUM,
                raw_data=key_list,
            )
        )

        if not self.export:
            return

        for key in key_list.get("Keys", []):
            try:
                payload = self.get_rpc_json(
                    target=context.target,
                    route="/api/v0/key/export",
                    params={"arg": key["Name"]},
                    raw=True,
                )
            except PluginException:
                continue

            context.report.add_issue(
                Issue(
                    title="Unauthorized Key Export",
                    description=(
                        "Anyone can export keys from the node. All secrets should be invalidated, "
                        "rotated, and reapplied. The endpoint must be protected against future "
                        "unauthorized use."
                    ),
                    severity=Severity.CRITICAL,
                    raw_data=payload,
                )
            )
