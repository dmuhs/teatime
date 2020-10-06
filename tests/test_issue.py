import pytest

from teatime import Issue, Severity


def test_valid_issue():
    title = "test"
    description = "test"
    severity = Severity.NONE
    raw_data = "test"
    issue = Issue(
        title=title, description=description, severity=severity, raw_data=raw_data
    )

    assert issue.title == title
    assert issue.description == description
    assert issue.severity == severity
    assert issue.raw_data == raw_data


@pytest.mark.parametrize(
    "issue,complete",
    (
        pytest.param(
            Issue(title="test", description="test", severity=Severity.NONE),
            True,
            id="complete no raw data",
        ),
        pytest.param(
            Issue(
                title="test",
                description="test",
                severity=Severity.NONE,
                raw_data="test",
            ),
            True,
            id="complete with raw data",
        ),
        pytest.param(
            Issue(title="test", description="test"),
            False,
            id="incomplete missing severity",
        ),
        pytest.param(
            Issue(title="test", severity=Severity.NONE),
            False,
            id="incomplete missing description",
        ),
        pytest.param(
            Issue(description="test", severity=Severity.NONE),
            False,
            id="incomplete missing title",
        ),
        pytest.param(
            Issue(),
            False,
            id="incomplete empty issue",
        ),
    ),
)
def test_issue_complete(issue: Issue, complete: bool):
    assert issue.is_complete() == complete


@pytest.mark.parametrize(
    "issue,severe",
    (
        pytest.param(Issue(severity=Severity.NONE), False, id="NONE"),
        pytest.param(Issue(severity=Severity.LOW), False, id="LOW"),
        pytest.param(Issue(severity=Severity.MEDIUM), True, id="MEDIUM"),
        pytest.param(Issue(severity=Severity.HIGH), True, id="HIGH"),
        pytest.param(Issue(severity=Severity.CRITICAL), True, id="CRITICAL"),
    ),
)
def test_issue_severe(issue: Issue, severe: bool):
    assert issue.is_severe() == severe


def test_issue_dict():
    title = "title"
    description = "description"
    severity = Severity.NONE
    raw_data = "raw_data"
    issue = Issue(title=title, description=description, severity=severity, raw_data=raw_data)
    issue_dict = issue.to_dict()

    assert issue_dict["title"] == title
    assert issue_dict["description"] == description
    assert issue_dict["severity"] == severity.name.lower()
    assert issue_dict["raw"] == '"raw_data"'
