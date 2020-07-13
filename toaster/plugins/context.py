from enum import Enum

from toaster.reporting.report import Report


class NodeType(Enum):
    GETH = 0
    PARITY = 1
    IPFS = 2


class Context:
    def __init__(self, target, report, node_type, **kwargs):
        self.target: str = target
        self.report: Report = report
        self.node_type: NodeType = node_type
        self.extra: dict = kwargs
