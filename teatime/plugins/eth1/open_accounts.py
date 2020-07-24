"""This module contains a plugin checking for account-related issues."""

import requests
from loguru import logger

from teatime.plugins import Context, Plugin, PluginException
from teatime.reporting import Issue, Severity


class AccountBalanceMixin:
    """A mixin class providing balance values for accounts.

    This mixin requires an Infura endpoint URL to be passed to look up the account's balance on the
    specified chain.
    """

    def __init__(self, infura_url: str):
        self.infura_url = infura_url

    def account_data(self, address: str) -> int:
        """Fetch additional data on the account.

        This method will call the passed Infura API URL and use the
        :code:`eth_getBalance` method of the specified account, on the
        latest block.

        :param address: The address to get the balance for
        :return: The account's balance as an integer
        """
        # TODO: Robust error handling
        rpc_response = requests.post(
            self.infura_url,
            json={
                "jsonrpc": "2.0",
                "method": "eth_getBalance",
                "params": [address, "latest"],
                "id": 0,
            },
        )
        return int(rpc_response.json()["result"], 16)


class OpenAccounts(Plugin, AccountBalanceMixin):
    """Check for any accounts registered on the node.

    Severity: Medium

    This plugin will use the :code:`eth_accounts` method to find accounts
    registered on the target node, and fetch the account's latest balance
    through Infura.
    """

    def __init__(self, infura_url: str):
        super().__init__(infura_url)

    def _check(self, context: Context) -> None:
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


class AccountUnlock(Plugin, AccountBalanceMixin):
    """Check whether any accounts on the node are weakly protected.

    Severity: Critical

    This plugin will use the :code:`eth_accounts` method to find accounts
    registered on the target node, and attempt to unlock the accounts with
    a given set of passwords. Each account is unlocked for a time of one
    second, the minimum time possible.

    Optionally, accounts below a minimum balance can be skipped.
    """

    def __init__(self, infura_url: str, wordlist=None, skip_below: int = None):
        super().__init__(infura_url)
        self.wordlist = wordlist or []
        self.skip_below = skip_below

    def _check(self, context: Context) -> None:
        accounts = self.get_rpc_json(context.target, "eth_accounts")
        for account in accounts:
            account_balance = self.account_data(account)
            if self.skip_below is not None and account_balance < self.skip_below:
                logger.debug(
                    f"Skipping {account} because balance {account_balance} < {self.skip_below}"
                )
                continue
            for password in self.wordlist:
                logger.debug(f"Trying password {password}")
                try:
                    payload = self.get_rpc_json(
                        context.target,
                        method="personal_unlockAccount",
                        params=[account, password, 1],  # unlock for only 1s
                    )
                except PluginException as e:
                    if str(e) == "Method not found":
                        logger.debug(
                            "Aborting wordlist attack because method is not supported"
                        )
                        # if the method is not supported, there is no point in checking
                        break
                    else:
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
