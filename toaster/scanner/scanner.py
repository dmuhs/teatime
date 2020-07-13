import time
from typing import List, Type

from toaster.plugins import Context, NodeType, Plugin
from toaster.reporting import Report


class Scanner:
    def __init__(self, target: str, node_type: NodeType, plugins: List[Type[Plugin]]):
        self.target = target
        self.plugins = (plugin() for plugin in plugins)
        self.node_type = node_type

    def run(self) -> Report:
        start = time.time()
        context = Context(
            target=self.target,
            report=Report(target=self.target),
            node_type=self.node_type,
        )
        for plugin in self.plugins:
            plugin.run(context)
        context.report.add_meta("elapsed", time.time() - start)
        return context.report
