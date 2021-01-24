"""This module contains a plugin checking for Parity/OpenEthereum upgrades."""
from teatime.plugins import Context, JSONRPCPlugin, NodeType
from teatime.reporting import Issue, Severity


class ParityUpgrade(JSONRPCPlugin):
    """Try to check for an available upgrade.

    Severity: Critical

    Parity/OpenEthereum:
    https://openethereum.github.io/wiki/JSONRPC-parity_set-module.html#parity_upgradeready
    """

    INTRUSIVE = False

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(context.target, method="parity_upgradeReady")
        context.report.add_issue(
            Issue(
                title="The node can be upgraded",
                description=(
                    "A new node upgrade has been detected using "
                    "the parity_upgradeReady RPC call."
                ),
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )
