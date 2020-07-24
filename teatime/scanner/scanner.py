"""This module contains a scanner class running various Plugins."""

import time
from typing import List

from loguru import logger

from teatime.plugins import Context, NodeType, Plugin
from teatime.reporting import Report


class Scanner:
    """The scanner class holding multiple plugins."""

    def __init__(self, target: str, node_type: NodeType, plugins: List[Plugin]):
        self.target = target
        self.plugins = plugins
        self.node_type = node_type

    def run(self) -> Report:
        """Run the scanner to generate a report.

        :return: A report object holding all findings
        """
        start = time.time()
        context = Context(
            target=self.target,
            report=Report(target=self.target),
            node_type=self.node_type,
        )
        for plugin in self.plugins:
            if plugin.INTRUSIVE:
                name = plugin.__class__.__name__
                logger.warning(
                    f"Plugin {name} is intrusive. Please make sure you have permission to run this scan on "
                    "the target. Don't be a douchebag."
                )
            plugin.run(context)
        context.report.add_meta("elapsed", time.time() - start)
        return context.report
