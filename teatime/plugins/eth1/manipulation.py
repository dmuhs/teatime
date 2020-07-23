from teatime.plugins import Context, NodeType, Plugin
from teatime.reporting import Issue, Severity


class ParityChangeCoinbase(Plugin):
    def _check(self, context: Context) -> None:
        """Try to change the coinbase address.

        .. todo:: Add details!

        :param context:
        """
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(
            context.target,
            method="parity_setAuthor",
            params=["0x25862BB810eEC365C4562FEAA8B2739B59B70A6a"],  # TODO: Author param
        )
        context.report.add_issue(
            Issue(
                title="Coinbase address change possible",
                description="Anyone can change the coinbase address and redirect miner payouts using the "
                "parity_setAuthor RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )


class ParityChangeTarget(Plugin):
    def _check(self, context: Context) -> None:
        """Try to change the target chain.

        .. todo:: Add details!

        :param context:
        """
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(
            context.target,
            method="parity_setChain",
            params=["mainnet"],  # TODO: target param
        )
        context.report.add_issue(
            Issue(
                title="Chain preset change possible",
                description="Anyone can change the node's target chain value using the parity_setChain RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )


class ParityChangeExtra(Plugin):
    def _check(self, context: Context) -> None:
        """Try to set the extra data field.

        .. todo:: Add details!

        :param context:
        """
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(
            context.target,
            method="parity_setExtraData",
            params=["toasted"],  # TODO: extra parameter
        )
        context.report.add_issue(
            Issue(
                title="Extra data change possible",
                description="Anyone can change the extra data attached to newly mined blocks using the "
                "parity_setExtraData RPC call.",
                raw_data=payload,
                severity=Severity.LOW,
            )
        )


class ParitySyncMode(Plugin):
    def _check(self, context: Context) -> None:
        """Try to set the node's sync mode.

        .. todo:: Add details!

        :param context:
        """
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(
            context.target, method="parity_setMode", params=["active"]
        )
        context.report.add_issue(
            Issue(
                title="The sync mode can be changed",
                description="Anyone can change the node's sync mode using the parity_setMode RPC call.",
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )
