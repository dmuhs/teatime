import pytest

from teatime import Issue, Report, Severity


def test_valid_report():
    target = "127.0.0.1:8545"
    report = Report(target, issues=[])
    assert report.issues == []
    assert report.target == target
    assert isinstance(report.id, str)
    assert isinstance(report.timestamp, str)
    assert report.meta == {}
    assert sorted(report.to_dict().keys()) == [
        "id",
        "issues",
        "meta",
        "ok",
        "target",
        "timestamp",
    ]


def test_report_add_issue():
    report = Report("127.0.0.1:8545")
    assert report.issues == []

    issue = Issue(title="test", description="test", severity=Severity.NONE)
    report.add_issue(issue)
    assert report.issues == [issue]
    assert len(report.to_dict()["issues"])


def test_report_add_incomplete_issue():
    report = Report("127.0.0.1:8545")
    assert report.issues == []

    issue = Issue(title="test", description="test")  # missing severity!
    with pytest.raises(ValueError):
        report.add_issue(issue)


def test_report_add_meta():
    report = Report("127.0.0.1:8545")
    assert report.meta == {}

    report.add_meta("test-key", "test-value")
    assert report.meta["test-key"] == "test-value"
    assert report.to_dict()["meta"]["test-key"] == "test-value"
