from toaster.plugins import Context, NodeType, Plugin
from toaster.reporting import Issue, Severity

TEST_PRIVKEY = "c7d26c414625a995584b347db39ebfce03129acb6386d5b2533a698614c138dc"
TEST_PASS = "fjaal38!dj==42"


class NewAccountCheck(Plugin):
    name = "RPC Account Import and Creation"
    version = "0.3.0"
    node_type = (NodeType.GETH, NodeType.PARITY)

    def __repr__(self):
        return f"<NewAccountCheck v{self.version}>"

    # TODO: Separate import and creation to two plugins

    def check_create_account(self, context):
        payload = self.get_rpc_json(
            target=context.target, method="personal_newAccount", params=[TEST_PASS]
        )
        context.report.add_issue(
            Issue(
                title="We managed to create a new account on your node",
                description="A new account can be generated on the node itself using the personal_newAccount RPC call.",
                raw_data=payload,
                severity=Severity.MEDIUM,
            )
        )

    def check_import_account(self, context):
        payload = self.get_rpc_json(
            target=context.target,
            method="personal_importRawKey",
            params=[TEST_PRIVKEY, TEST_PASS],
        )
        context.report.add_issue(
            Issue(
                title="We managed to import an account on your node",
                description="A private key can be imported on the node to initialize an account using the personal_importRawKey RPC call.",
                raw_data=payload,
                severity=Severity.MEDIUM,
            )
        )

    def run(self, context: Context):
        # SCAN[MEDIUM]: create account
        self.run_catch("Account Generation", self.check_create_account, context)

        if context.node_type == NodeType.GETH:
            # SCAN[MEDIUM]: GETH import private key
            self.run_catch("Geth Account Import", self.check_import_account, context)

        context.report.add_meta(self.name, self.version)
