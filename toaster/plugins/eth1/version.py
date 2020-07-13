"""This module contains a plugin to check for stale node versions."""

import re

import requests

from toaster.plugins import Context, NodeType, Plugin
from toaster.reporting import Issue, Severity

SEMVER_REGEX = r"\d+.\d+.\d+"


class NodeVersionCheck(Plugin):
    """A plugin to check whether a node version is stale."""

    name = "RPC Node Version Information"
    version = "0.2.0"
    node_type = (NodeType.GETH, NodeType.PARITY)

    def __repr__(self):
        return f"<NodeVersionCheck v{self.version}>"

    def check_stale_version(self, context):
        """Check whether a given node's version is stale.

        .. todo:: Add details!

        :param context:
        """
        client_version = self.get_rpc_json(context.target, "web3_clientVersion")
        context.report.add_issue(
            Issue(
                title=self.name,
                description="The node surfaces it's version information",
                raw_data=client_version,
                severity=Severity.NONE,
            )
        )
        # TODO: Handle missing version
        client_semver = re.findall(SEMVER_REGEX, client_version)[0]
        node_semver = (
            self.latest_geth_release()
            if context.node_type == NodeType.GETH
            else self.latest_parity_release()
        )
        if client_semver != node_semver:
            context.report.add_issue(
                Issue(
                    title="Node version out of date",
                    description=f"{client_semver} != {node_semver}",
                    raw_data=client_version,
                    severity=Severity.HIGH,
                )
            )

    @staticmethod
    def latest_geth_release():
        """Fetch the latest Geth release.

        .. todo:: Add details!

        :return:
        """
        # TODO: Handle missing versions
        resp = requests.get(
            "https://api.github.com/repos/ethereum/go-ethereum/releases/latest"
        )
        tag = re.findall(SEMVER_REGEX, resp.json()["tag_name"])[0]
        return tag

    @staticmethod
    def latest_parity_release():
        """Fetch the latest Parity/OpenEthereum release.

        .. todo:: Add details!

        :return:
        """
        resp = requests.get(
            "https://api.github.com/repos/openethereum/openethereum/releases/latest"
        )
        tag = re.findall(SEMVER_REGEX, resp.json()["tag_name"])[0]
        return tag

    def run(self, context: Context):
        """Run the plugin to detect stale node versions.

        .. todo:: Add details!

        :param context:
        """
        # SCAN[LOW]: Version information
        # SCAN[HIGH]: Old client version
        self.run_catch("Version check", self.check_stale_version, context)

        context.report.add_meta(self.name, self.version)
