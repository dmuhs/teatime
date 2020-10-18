from uuid import uuid4

import pytest

from teatime import Issue, Report, Severity

TEST_UUID = str(uuid4())


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


def test_report_repr():
    report = Report(target="127.0.0.1:8545", issues=[None, None])
    assert report.target in str(report)
    assert str(len(report.issues)) in str(report)


@pytest.mark.parametrize(
    "report_1,report_2,expected",
    (
        pytest.param(
            Report(
                uuid=TEST_UUID, target="127.0.0.1:8545", issues=[None], timestamp="lol"
            ),
            Report(
                uuid=TEST_UUID, target="127.0.0.1:8545", issues=[None], timestamp="lol"
            ),
            True,
            id="equals",
        ),
        pytest.param(
            Report(uuid=TEST_UUID, target="127.0.0.1:8545", issues=[None]),
            Report(uuid=str(uuid4()), target="127.0.0.1:8545", issues=[None]),
            False,
            id="uuid different",
        ),
        pytest.param(
            Report(uuid=TEST_UUID, target="127.0.0.1:8545", issues=[None]),
            Report(uuid=TEST_UUID, target="lel", issues=[None]),
            False,
            id="target different",
        ),
        pytest.param(
            Report(uuid=TEST_UUID, target="127.0.0.1:8545", issues=[None]),
            Report(uuid=TEST_UUID, target="127.0.0.1:8545", issues=[]),
            False,
            id="issues different",
        ),
    ),
)
def test_report_equality(report_1, report_2, expected):
    assert (report_1 == report_2) == expected
