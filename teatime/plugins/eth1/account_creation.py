"""This module contains a plugin with checks for account creation."""

from teatime.plugins import JSONRPCPlugin
from teatime.reporting import Issue, Severity


class AccountCreation(JSONRPCPlugin):
    """Detect whether it's possible to create an account on the node.

    Severity: Medium

    This check will try to generate a new account on the node using the
    :code:`personal_newAccount` and lock the new account with the given
    password.

    Geth:
    https://geth.ethereum.org/docs/rpc/ns-personal#personal_newaccount
    Parity/OpenEthereum:
    https://openethereum.github.io/wiki/JSONRPC-personal-module#personal_newaccount
    """

    INTRUSIVE = True

    def __init__(self, test_password: str):
        self.test_password = test_password

    def _check(self, context):
        payload = self.get_rpc_json(
            target=context.target,
            method="personal_newAccount",
            params=[self.test_password],
        )
        context.report.add_issue(
            Issue(
                title="We managed to create a new account on your node",
                description=(
                    "A new account can be generated on the node "
                    "itself using the personal_newAccount RPC call."
                ),
                raw_data=payload,
                severity=Severity.MEDIUM,
            )
        )
