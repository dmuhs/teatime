"""This module contains plugins around setting vital execution parameters."""
from teatime.plugins import Context, JSONRPCPlugin, NodeType
from teatime.reporting import Issue, Severity


class ParityChangeCoinbase(JSONRPCPlugin):
    """Try to change the coinbase address.

    Severity: Critical

    Parity/OpenEthereum:
    https://openethereum.github.io/wiki/JSONRPC-parity_set-module#parity_setauthor
    """

    INTRUSIVE = True

    def __init__(self, author: str):
        self.author = author

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(
            context.target,
            method="parity_setAuthor",
            params=[self.author],
        )
        context.report.add_issue(
            Issue(
                title="Coinbase address change possible",
                description=(
                    "Anyone can change the coinbase address "
                    "and redirect miner payouts using the "
                    "parity_setAuthor RPC call."
                ),
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )


class ParityChangeTarget(JSONRPCPlugin):
    """Try to change the target chain.

    Severity: Critical

    Parity/OpenEthereum:
    https://openethereum.github.io/wiki/JSONRPC-parity_set-module#parity_setchain
    """

    INTRUSIVE = True

    def __init__(self, target_chain: str):
        self.target_chain = target_chain

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(
            context.target,
            method="parity_setChain",
            params=[self.target_chain],
        )
        context.report.add_issue(
            Issue(
                title="Chain preset change possible",
                description=(
                    "Anyone can change the node's target chain "
                    "value using the parity_setChain RPC call."
                ),
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )


class ParityChangeExtra(JSONRPCPlugin):
    """Try to set the extra data field.

    Severity: Low

    Parity/OpenEthereum:
    https://openethereum.github.io/wiki/JSONRPC-parity_set-module#parity_setextradata
    """

    INTRUSIVE = True

    def __init__(self, extra_data: str):
        self.extra_data = extra_data

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(
            context.target,
            method="parity_setExtraData",
            params=[self.extra_data],
        )
        context.report.add_issue(
            Issue(
                title="Extra data change possible",
                description=(
                    "Anyone can change the extra data attached "
                    "to newly mined blocks using the "
                    "parity_setExtraData RPC call."
                ),
                raw_data=payload,
                severity=Severity.LOW,
            )
        )


class ParitySyncMode(JSONRPCPlugin):
    """Try to set the node's sync mode.

    Severity: Critical

    Parity/OpenEthereum:
    https://openethereum.github.io/wiki/JSONRPC-parity_set-module#parity_setmode
    """

    INTRUSIVE = True

    def __init__(self, mode: str):
        self.mode = mode

    def _check(self, context: Context) -> None:
        if context.node_type != NodeType.PARITY:
            return

        payload = self.get_rpc_json(
            context.target, method="parity_setMode", params=[self.mode]
        )
        context.report.add_issue(
            Issue(
                title="The sync mode can be changed",
                description=(
                    "Anyone can change the node's sync "
                    "mode using the parity_setMode RPC call."
                ),
                raw_data=payload,
                severity=Severity.CRITICAL,
            )
        )
