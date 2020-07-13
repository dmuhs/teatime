"""This module contains a scanner class running various Plugins."""

import time
from typing import List, Type

from toaster.plugins import Context, NodeType, Plugin
from toaster.reporting import Report


class Scanner:
    """The scanner class holding multiple plugins.

    .. todo:: Add details!

    """

    def __init__(self, target: str, node_type: NodeType, plugins: List[Type[Plugin]]):
        self.target = target
        self.plugins = (plugin() for plugin in plugins)
        self.node_type = node_type

    def run(self) -> Report:
        """Run the scanner to generate a report.

        .. todo:: Add details!

        :return:
        """
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
