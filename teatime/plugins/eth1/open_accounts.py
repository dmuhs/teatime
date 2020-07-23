"""This module contains a plugin checking for account-related issues."""

import requests

from teatime.plugins import Context, Plugin, PluginException
from teatime.reporting import Issue, Severity


# TODO: Parity open vault checks


class OpenAccounts(Plugin):
    def _check(self, context: Context) -> None:
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

    @staticmethod
    def account_data(address: str) -> dict:
        """Fetch additional data on the account.

        .. todo:: Add details!

        :param address:
        :return:
        """
        # TODO: Robust error handling
        rpc_response = requests.post(
            "https://mainnet.infura.io/v3/a17bd235fd4147259d03784b24bd3a62",  # TODO: make param
            json={
                "jsonrpc": "2.0",
                "method": "eth_getBalance",
                "params": [address, "latest"],
                "id": 0,
            },
        )
        return {"balance": int(rpc_response.json()["result"], 16)}


class AccountUnlock(Plugin):
    """This plugin checks for open and weakly-protected accounts."""

    def __init__(self, wordlist=None):
        self.wordlist = wordlist or []

    def _check(self, context: Context) -> None:
        """Check whether any accounts on the node are weakly protected.

        .. todo:: Add details!

        :param context:
        """

        accounts = self.get_rpc_json(context.target, "eth_accounts")
        for account in accounts:
            for password in self.wordlist:
                try:
                    payload = self.get_rpc_json(
                        context.target,
                        method="personal_unlockAccount",
                        params=[account, password, 1],  # unlock for only 1s
                    )
                except PluginException:
                    # explicitly catch here to not interrupt wordlist loop
                    continue

                context.report.add_issue(
                    Issue(
                        title="Weak password detected!",
                        description=f"The account ({account}) is only protected by a weak password ({password})",
                        raw_data=payload,
                        severity=Severity.CRITICAL,
                    )
                )
