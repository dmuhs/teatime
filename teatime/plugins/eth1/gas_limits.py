from teatime.plugins import Context, NodeType, Plugin
from teatime.reporting import Issue, Severity


class ParityGasCeiling(Plugin):
    def _check(self, context: Context) -> None:
        """Try to set the gas ceiling.

        .. todo:: Add details!

        :param context:
        """
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(
            context.target, method="parity_setGasCeilTarget", params=["0x2540be400"]
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
    def _check(self, context: Context) -> None:
        """Try to set the gas floor.

        .. todo:: Add details!

        :param context:
        """
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
