"""This module contains a plugin to check for stale node versions."""

import json
import re

import requests

from teatime.plugins import Context, JSONRPCPlugin, NodeType, PluginException
from teatime.reporting import Issue, Severity

SEMVER_REGEX = r"\d+.\d+.\d+"


class NodeVersion(JSONRPCPlugin):
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

    INTRUSIVE = False

    def __init__(
        self,
        geth_url: str = "https://api.github.com/repos/ethereum/go-ethereum/releases/latest",
        parity_url: str = "https://api.github.com/repos/openethereum/openethereum/releases/latest",
    ):
        self.geth_url = geth_url
        self.parity_url = parity_url

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
        try:
            client_semver = re.findall(SEMVER_REGEX, client_version)[0]
        except IndexError:
            raise PluginException(
                f"Could not extract the client version from string {client_version}"
            )

        if context.node_type == NodeType.GETH:
            node_semver = self.latest_repo_release(self.geth_url)
        elif context.node_type == NodeType.PARITY:
            node_semver = self.latest_repo_release(self.parity_url)
        else:
            raise PluginException(
                f"No repo known for node type {context.node_type}"
            )  # pragma: no cover

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
    def latest_repo_release(url: str) -> str:
        """Fetch the latest release tag for the given repository URL.

        This method will use the public Github API to fetch the latest release tag
        for the given repository.

        :return: The repo's semver as a string
        """

        resp = requests.get(url)
        try:
            repo_information = resp.json()
        except json.JSONDecodeError:
            raise PluginException(f"Could not decode API response {resp.text}")

        try:
            tag = re.findall(SEMVER_REGEX, repo_information["tag_name"])[0]
        except (KeyError, IndexError):
            raise PluginException(
                f"Could not extract repo tag from response {repo_information}"
            )

        return tag
