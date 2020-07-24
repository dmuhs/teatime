"""This module contains a plugin to check for stale node versions."""

import re

import requests

from teatime.plugins import Context, NodeType, Plugin
from teatime.reporting import Issue, Severity

SEMVER_REGEX = r"\d+.\d+.\d+"


class NodeVersion(Plugin):
    """Check whether a given node's version is stale.

    Severity: None/High

    This plugin will fetch the client's version string, and attempt to extract the
    node's semantic version number. For Geth and Parity/OpenEthereum, it will try to
    fetch the latest repository tag and compare both versions. If there is a mismatch,
    an issue is logged about the node version being stale. In any case, an informational
    issue will be logged containing the version string.

    Parity/OpenEthereum: https://openethereum.github.io/wiki/JSONRPC-web3-module#web3_clientversion
    Geth: I couldn't find the web3 namespace in the official docs :(
    """

    def _check(self, context: Context) -> None:
        client_version = self.get_rpc_json(context.target, "web3_clientVersion")
        context.report.add_issue(
            Issue(
                title=self.__class__.__name__,
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
    def latest_geth_release() -> str:
        """Fetch the latest Geth release.

        This method will use the public Github API to fetch the latest release tag
        for the Geth repository.

        :return: The Geth semver as a string
        """
        # TODO: Handle missing versions
        resp = requests.get(
            "https://api.github.com/repos/ethereum/go-ethereum/releases/latest"  # TODO: make parameter
        )
        tag = re.findall(SEMVER_REGEX, resp.json()["tag_name"])[0]
        return tag

    @staticmethod
    def latest_parity_release() -> str:
        """Fetch the latest Parity/OpenEthereum release.

        This method will use the public Github API to fetch the latest release tag
        for the OpenEthereum repository.

        :return: The OpenEthereum semver as a string
        """
        resp = requests.get(
            "https://api.github.com/repos/openethereum/openethereum/releases/latest"  # TODO: make parameter
        )
        tag = re.findall(SEMVER_REGEX, resp.json()["tag_name"])[0]
        return tag
