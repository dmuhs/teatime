"""This module contains a plugin with checks for account creation."""

from teatime.plugins import Context, NodeType, Plugin
from teatime.reporting import Issue, Severity


class AccountCreation(Plugin):
    """Detect account creation weaknesses."""

    def __init__(self, test_password: str):
        self.test_password = test_password

    def _check(self, context):
        """Detect whether it's possible to create an account on the node.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(
            target=context.target,
            method="personal_newAccount",
            params=[self.test_password],
        )
        context.report.add_issue(
            Issue(
                title="We managed to create a new account on your node",
                description="A new account can be generated on the node itself using the personal_newAccount RPC call.",
                raw_data=payload,
                severity=Severity.MEDIUM,
            )
        )
