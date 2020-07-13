"""This module contains a plugin checking for account-related issues."""

import requests

from toaster.plugins import Context, NodeType, Plugin
from toaster.reporting import Issue, Severity

DEFAULT_PASSWORDS = [
    "",  # lol no way
    "hunter2",  # from parity docs
    "admin",
    "password",
    "test",
    "ethereum",
]


# TODO: Parity open vault checks
class OpenAccountsCheck(Plugin):
    """This plugin checks for open and weakly-protected accounts."""

    name = "RPC Open Account Detection"
    version = "0.4.0"
    node_type = (NodeType.GETH, NodeType.PARITY)

    def __repr__(self):
        return f"<OpenAccountsCheck v{self.version}>"

    def check_accounts(self, context):
        """Check for any accounts registered on the node.

        .. todo:: Add details!

        :param context:
        """
        accounts = self.get_rpc_json(context.target, "eth_accounts")
        for account in accounts:
            context.report.add_issue(
                Issue(
                    title="Found account",
                    description=f"Account: {account} Balance: {self.account_data(account)}",
                    raw_data=account,
                    severity=Severity.MEDIUM,
                )
            )

    def check_account_bruteforce(self, context):
        """Check whether any accounts on the node are weakly protected.

        .. todo:: Add details!

        :param context:
        """
        # TODO: custom wordlist
        accounts = self.get_rpc_json(context.target, "eth_accounts")
        for account in accounts:
            for password in DEFAULT_PASSWORDS:
                payload = self.get_rpc_json(
                    context.target,
                    method="personal_unlockAccount",
                    params=[account, password, 1],  # unlock for only 1s
                )
                context.report.add_issue(
                    Issue(
                        title="Weak password detected!",
                        description=f"The account ({account}) is only protected by a weak password ({password})",
                        raw_data=payload,
                        severity=Severity.CRITICAL,
                    )
                )

    @staticmethod
    def account_data(address: str):
        """Fetch additional data on the account.

        .. todo:: Add details!

        :param address:
        :return:
        """
        # TODO: Robust error handling
        rpc_response = requests.post(
            "https://mainnet.infura.io/v3/a17bd235fd4147259d03784b24bd3a62",
            json={
                "jsonrpc": "2.0",
                "method": "eth_getBalance",
                "params": [address, "latest"],
                "id": 0,
            },
        )
        return {"balance": int(rpc_response.json()["result"], 16)}

    def run(self, context: Context):
        """Run account-related checks for vulnerabilities and weaknesses.

        .. todo:: Add details!

        :param context:
        """
        # TODO: Actions with the accounts possible?
        # SCAN[MEDIUM]: Account registered on node
        self.run_catch("Node accounts", self.check_accounts, context)
        # SCAN[CRITICAL]: Account has weak auth credentials
        self.run_catch("Account bruteforce", self.check_account_bruteforce, context)

        context.report.add_meta(self.name, self.version)
