"""This module contains a plugin with checks for account creation."""

from teatime.plugins import Context, NodeType, Plugin
from teatime.reporting import Issue, Severity


class NewAccountCheck(Plugin):
    """Detect account import and creation weaknesses."""

    name = "RPC Account Import and Creation"
    version = "0.3.1"

    def __repr__(self):
        return f"<NewAccountCheck v{self.version}>"

    def __init__(self, test_privkey: str, test_password: str):
        self.test_privkey = test_privkey
        self.test_password = test_password

    # TODO: Separate import and creation to two plugins

    def check_create_account(self, context: Context) -> None:
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

    def check_import_account(self, context: Context) -> None:
        """Detect whether it's possible to import a private key on the node.

        .. todo:: Add details!

        :param context:
        """
        payload = self.get_rpc_json(
            target=context.target,
            method="personal_importRawKey",
            params=[self.test_password, self.test_password],
        )
        context.report.add_issue(
            Issue(
                title="We managed to import an account on your node",
                description="A private key can be imported on the node to initialize an account using the "
                "personal_importRawKey RPC call.",
                raw_data=payload,
                severity=Severity.MEDIUM,
            )
        )

    def run(self, context: Context) -> None:
        """Run the account creation plugin.

        .. todo:: Add details!

        :param context:
        """
        # SCAN[MEDIUM]: create account
        self.run_catch("Account Generation", self.check_create_account, context)

        if context.node_type == NodeType.GETH:
            # SCAN[MEDIUM]: GETH import private key
            self.run_catch("Geth Account Import", self.check_import_account, context)

        context.report.add_meta(self.name, self.version)
