"""This module contains plugins around the gas-setting RPC endpoints."""

from teatime.plugins import Context, JSONRPCPlugin, NodeType
from teatime.reporting import Issue, Severity


class ParityGasCeiling(JSONRPCPlugin):
    """Try to set a new gas ceiling target for mined blocks.

    Severity: Critical

    Parity/OpenEthereum:
    https://openethereum.github.io/wiki/JSONRPC-parity_set-module#parity_setgasceiltarget
    """

    INTRUSIVE = True

    def __init__(self, gas_target: int):
        self.gas_target = hex(gas_target)

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(
            context.target,
            method="parity_setGasCeilTarget",
            params=[self.gas_target],
        )
        context.report.add_issue(
            Issue(
                title="Gas ceiling target can be changed",
                description=(
                    "Anyone can change the gas ceiling value "
                    "using the parity_setGasCeilTarget RPC call."
                ),
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )


class ParityGasFloor(JSONRPCPlugin):
    """Try to set a new gas floor target for mined blocks.

    Severity: Critical

    Parity/OpenEthereum:
    https://openethereum.github.io/wiki/JSONRPC-parity_set-module#parity_setgasfloortarget
    """

    INTRUSIVE = True

    def __init__(self, gas_floor: int):
        self.gas_floor = hex(gas_floor)

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(
            context.target, method="parity_setGasFloorTarget", params=[self.gas_floor]
        )
        context.report.add_issue(
            Issue(
                title="Gas floor target can be changed",
                description=(
                    "Anyone can change the gas floor value using "
                    "the parity_setGasFloorTarget RPC call."
                ),
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )
