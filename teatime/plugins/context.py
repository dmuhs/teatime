"""This module contains the context that is passed to plugins."""

from enum import Enum

from teatime.reporting.report import Report


class NodeType(Enum):
    """An Enum denoting a node type to scan.

    Currently, only Geth and Parity/OpenEthereum are supported.
    Future considerations are:
    - IPFS
    - Filecoin
    - ETH2 clients
    """

    GETH = 0
    PARITY = 1
    IPFS = 2


class Context:
    """The context object passed between plugins."""

    def __init__(self, target, report, node_type, **kwargs):
        self.target: str = target
        self.report: Report = report
        self.node_type: NodeType = node_type
        self.extra: dict = kwargs
