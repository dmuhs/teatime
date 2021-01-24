"""This module contains a plugin detect a node's exposed web interface."""

import requests

from teatime import Context, Issue, NodeType, Severity
from teatime.plugins.base import IPFSRPCPlugin, handle_connection_errors


class WebUIEnabled(IPFSRPCPlugin):
    """Attempt to access the target's Web UI.

    Severity: HIGH

    Anyone can access the Web UI. A plethora of administrative
    actions can be done through the web interface. This includes
    changing the node's configuration, which can be used to open
    other potential attack vectors.
    """

    INTRUSIVE = False

    def __init__(self, route: str = "/webui"):
        self.route = route

    @staticmethod
    @handle_connection_errors
    def fetch_ui(target, route):
        resp = requests.get(target + route)
        return resp.url, resp.status_code

    def _check(self, context: Context):
        if context.node_type != NodeType.IPFS:
            return

        payload, status = self.fetch_ui(context.target, self.route)

        if status == 200:
            context.report.add_issue(
                Issue(
                    title="Exposed Web UI",
                    description=(
                        "Anyone can access the Web UI. A plethora of administrative "
                        "actions can be done through the web interface. This includes "
                        "changing the node's configuration, which can be used to open "
                        "other potential attack vectors."
                    ),
                    severity=Severity.HIGH,
                    raw_data=payload,
                )
            )
