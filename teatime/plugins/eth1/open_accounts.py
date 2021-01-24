"""This module contains a plugin checking for account-related issues."""

from loguru import logger

from teatime.plugins import Context, JSONRPCPlugin, PluginException
from teatime.reporting import Issue, Severity


class OpenAccounts(JSONRPCPlugin):
    """Check for any accounts registered on the node.

    Severity: Medium

    This plugin will use the :code:`eth_accounts` method to find accounts
    registered on the target node, and fetch the account's latest balance
    through Infura.
    """

    INTRUSIVE = False

    def __init__(self, infura_url: str):
        self.infura_url = infura_url

    def _check(self, context: Context) -> None:
        accounts = self.get_rpc_json(context.target, "eth_accounts")
        for account in accounts:
            balance = self.get_rpc_int(
                self.infura_url, method="eth_getBalance", params=[account, "latest"]
            )
            context.report.add_issue(
                Issue(
                    title="Found account",
                    description=f"Account: {account} Balance: {balance}",
                    raw_data=account,
                    severity=Severity.MEDIUM,
                )
            )


class AccountUnlock(JSONRPCPlugin):
    """Check whether any accounts on the node are weakly protected.

    Severity: Critical

    This plugin will use the :code:`eth_accounts` method to find accounts
    registered on the target node, and attempt to unlock the accounts with
    a given set of passwords. Each account is unlocked for a time of one
    second, the minimum time possible.

    Optionally, accounts below a minimum balance can be skipped.
    """

    INTRUSIVE = True

    def __init__(self, infura_url: str, wordlist=None, skip_below: int = None):
        self.infura_url = infura_url
        self.wordlist = wordlist or []
        self.skip_below = skip_below

    def _check(self, context: Context) -> None:
        accounts = self.get_rpc_json(context.target, "eth_accounts")
        for account in accounts:
            balance = self.get_rpc_int(
                self.infura_url, method="eth_getBalance", params=[account, "latest"]
            )
            if self.skip_below is not None and balance < self.skip_below:
                logger.debug(
                    f"Skipping {account} because balance {balance} < {self.skip_below}"
                )
                continue
            logger.debug(f"Trying passwords with {account} with balance {balance}")
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
                        description=(
                            f"The account ({account}) is only protected "
                            f"by a weak password ({password})"
                        ),
                        raw_data=payload,
                        severity=Severity.CRITICAL,
                    )
                )
