"""This module contains plugins to probe a node's version and find outdated dependencies."""

import json

from teatime import Context, Issue, NodeType, Severity
from teatime.plugins.base import IPFSRPCPlugin


class Version(IPFSRPCPlugin):
    """Detect whether the node's version endpoint is available.

    Severity: Low

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-version

    The version endpoint reveals the Go version IPFS has been compiled with,
    along with repository and system information, which may contain sensitive
    data.
    """

    INTRUSIVE = False

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        payload = self.get_rpc_json(
            target=context.target,
            route="/api/v0/version",
        )

        context.report.add_issue(
            Issue(
                title="Version Information Leak",
                description=(
                    "Version information of the node and its execution environment is exposed. "
                    "This allows an attacker to obtain information about the system's Go version, "
                    "operating system, as well as the IPFS node's version and origin repository"
                ),
                severity=Severity.LOW,
                raw_data=payload,
            )
        )


class DependencyVersion(IPFSRPCPlugin):
    """Detect whether the node's version endpoint is available.

    Severity: Low

    Endpoint: https://docs.ipfs.io/reference/http/api/#api-v0-version-deps

    The version endpoint reveals the Go version IPFS has been compiled with,
    along with repository and system information, which may contain sensitive
    data.
    """

    INTRUSIVE = False

    def __init__(self, check_dependencies: bool = True):
        self.check_dependencies = check_dependencies

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        payload = self.get_rpc_json(
            target=context.target, route="/api/v0/version/deps", raw=True
        ).split("\n")
        payload = [json.loads(s) for s in payload if s != ""]

        context.report.add_issue(
            Issue(
                title="Dependency Version Information Leak",
                description=(
                    "Dependency version information is exposed. "
                    "This allows an attacker to obtain information about the system's Go version, "
                    "operating system, as well as the IPFS node's version and origin repository"
                ),
                severity=Severity.LOW,
                raw_data=payload,
            )
        )

        if not self.check_dependencies:
            return

        for dependency in payload:
            if dependency.get("ReplacedBy", "") != "":
                context.report.add_issue(
                    Issue(
                        title="Outdated Dependency",
                        description=(
                            "The IPFS node has been compiled with an old dependency version. "
                            "Consider upgrading it for the latest feature and security updates."
                        ),
                        severity=Severity.LOW,
                        raw_data=dependency,
                    )
                )
