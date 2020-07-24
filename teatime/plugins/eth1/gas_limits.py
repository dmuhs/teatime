"""This module contains plugins around the gas-setting RPC endpoints."""

from teatime.plugins import Context, NodeType, Plugin
from teatime.reporting import Issue, Severity


class ParityGasCeiling(Plugin):
    """Try to set a new gas ceiling target for mined blocks.

    Severity: Critical

    Parity/OpenEthereum: https://openethereum.github.io/wiki/JSONRPC-parity_set-module#parity_setgasceiltarget
    """

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(
            context.target,
            method="parity_setGasCeilTarget",
            params=["0x2540be400"],  # TODO: parametrize
        )
        context.report.add_issue(
            Issue(
                title="Gas ceiling target can be changed",
                description="Anyone can change the gas ceiling value using the parity_setGasCeilTarget RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )


class ParityGasFloor(Plugin):
    """Try to set a new gas floor target for mined blocks.

    Severity: Critical

    Parity/OpenEthereum: https://openethereum.github.io/wiki/JSONRPC-parity_set-module#parity_setgasfloortarget
    """

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(
            context.target, method="parity_setGasFloorTarget", params=["0x0"]
        )
        context.report.add_issue(
            Issue(
                title="Gas floor target can be changed",
                description="Anyone can change the gas floor value using the parity_setGasFloorTarget RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )
