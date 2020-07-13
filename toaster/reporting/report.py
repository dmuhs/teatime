from datetime import datetime
from uuid import uuid4

from toaster.reporting.issue import Issue


class Report:
    def __init__(self, target, issues=None):
        self.id = str(uuid4())
        self.target = target
        self.timestamp = datetime.now().isoformat()
        self.issues = issues or []
        self.meta = {}

    def add_issue(self, issue: Issue):
        if not issue.is_complete():
            raise ValueError("Encountered incomplete issue")
        self.issues.append(issue)

    def add_meta(self, key, value):
        self.meta[key] = value

    def to_dict(self):
        return {
            "id": self.id,
            "target": self.target,
            "issues": [i.to_dict() for i in self.issues],
            "timestamp": self.timestamp,
            "meta": self.meta,
            "ok": any([i.is_severe() for i in self.issues]),
        }
