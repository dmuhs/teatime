"""This module contains the reporting functionality."""

from datetime import datetime
from typing import List
from uuid import uuid4

from teatime.reporting.issue import Issue


class Report:
    """A report class holding multiple issues and meta data."""

    def __init__(self, target, uuid: str = None, issues=None, timestamp: str = None):
        self.id: str = uuid or str(uuid4())
        self.target: str = target
        self.timestamp: str = timestamp or datetime.now().isoformat()
        self.issues: List[Issue] = issues or []
        self.meta: dict = {}

    def add_issue(self, issue: Issue):
        """Add an issue to the report.

        :param issue: The issue object to add
        """
        if not issue.is_complete():
            raise ValueError("Encountered incomplete issue")
        self.issues.append(issue)

    def add_meta(self, key, value):
        """Add a meta data key-value pair to the report.

        :param key: The meta data key name
        :param value: The meta data key's value to attach
        """
        self.meta[key] = value

    def to_dict(self) -> dict:
        """Convert the report and its issues to a Python dict.

        :return: The report's representation as a dict
        """
        return {
            "id": self.id,
            "target": self.target,
            "issues": [i.to_dict() for i in self.issues],
            "timestamp": self.timestamp,
            "meta": self.meta,
            "ok": any(i.is_severe() for i in self.issues) if self.issues else True,
        }

    def __eq__(self, other: "Report"):
        return all(
            (
                self.id == other.id,
                self.target == other.target,
                self.timestamp == other.timestamp,
                self.issues == other.issues,
                self.meta == other.meta,
            )
        )

    def __repr__(self):
        return f"<Report target={self.target} issues={len(self.issues)}>"
