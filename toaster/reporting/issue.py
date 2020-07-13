import json
from enum import Enum
from uuid import uuid4


class Severity(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self):
        return self.name


class Issue:
    def __init__(
        self,
        title: str = None,
        description: str = None,
        severity: Severity = None,
        raw_data: str = None,
    ):
        self.id = str(uuid4())
        self.title = title
        self.description = description
        self.severity = severity
        self.raw_data = raw_data

    def is_severe(self):
        return not (self.severity == Severity.LOW or self.severity.NONE)

    def is_complete(self):
        return all(
            (
                self.id,
                self.title is not None,
                self.description is not None,
                self.severity is not None,
            )
        )

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": str(self.severity).lower(),
            "raw": json.dumps(self.raw_data),
        }
