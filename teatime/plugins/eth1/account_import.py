"""This module holds the plugin checking for accound imports."""
from teatime.plugins import Context, NodeType, Plugin
from teatime.reporting import Issue, Severity


class GethAccountImport(Plugin):
    """Detect whether it's possible to import an account on the node.

    Severity: Medium

    This check will try to import an existing account on the node using the
    :code:`personal_importRawKey` and lock the new account with the given
    password. This check only works with Geth client nodes.

    Geth: https://geth.ethereum.org/docs/rpc/ns-personal#personal_importrawkey
    """

    INTRUSIVE = True

    def __init__(self, test_password: str):
        self.test_password = test_password

    def _check(self, context: "Context"):
        if context.node_type != NodeType.GETH:
            return

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
