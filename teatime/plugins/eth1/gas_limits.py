"""This module contains plugins around the gas-setting RPC endpoints."""

from teatime.plugins import Context, NodeType, Plugin
from teatime.reporting import Issue, Severity


class ParityGasCeiling(Plugin):
    """Try to set a new gas ceiling target for mined blocks.

    Severity: Critical

    Parity/OpenEthereum: https://openethereum.github.io/wiki/JSONRPC-parity_set-module#parity_setgasceiltarget
    """

    INTRUSIVE = True

    def __init__(self, gas_target: str):
        self.gas_target = gas_target

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(
            context.target, method="parity_setGasCeilTarget", params=[self.gas_target],
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

    INTRUSIVE = True

    def __init__(self, gas_floor: str):
        self.gas_floor = gas_floor

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(
            context.target, method="parity_setGasFloorTarget", params=[self.gas_floor]
        )
        context.report.add_issue(
            Issue(
                title="Gas floor target can be changed",
                description="Anyone can change the gas floor value using the parity_setGasFloorTarget RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )
