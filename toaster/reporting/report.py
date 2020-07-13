"""This module contains the reporting functionality."""

from datetime import datetime
from uuid import uuid4

from toaster.reporting.issue import Issue


class Report:
    """A report class holding multiple issues and meta data.

    .. todo:: Add details!

    """
    def __init__(self, target, issues=None):
        self.id = str(uuid4())
        self.target = target
        self.timestamp = datetime.now().isoformat()
        self.issues = issues or []
        self.meta = {}

    def add_issue(self, issue: Issue):
        """Add an issue to the report.

        .. todo:: Add details!

        :param issue:
        """
        if not issue.is_complete():
            raise ValueError("Encountered incomplete issue")
        self.issues.append(issue)

    def add_meta(self, key, value):
        """Add a meta data key-value pair to the report.

        .. todo:: Add details!

        :param key:
        :param value:
        """
        self.meta[key] = value

    def to_dict(self):
        """Convert the report and its issues to a Python dict.

        .. todo:: Add details!

        :return:
        """
        return {
            "id": self.id,
            "target": self.target,
            "issues": [i.to_dict() for i in self.issues],
            "timestamp": self.timestamp,
            "meta": self.meta,
            "ok": any([i.is_severe() for i in self.issues]),
        }
