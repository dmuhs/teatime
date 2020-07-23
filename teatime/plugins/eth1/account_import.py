from teatime.plugins import Context, Plugin, NodeType
from teatime.reporting import Issue, Severity


class AccountImport(Plugin):
    """Detect account import weaknesses."""

    def __init__(self, test_password: str):
        self.test_password = test_password

    def _check(self, context: "Context"):
        """Detect whether it's possible to import an account on the node.

        .. todo:: Add details!

        :param context:
        """
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
