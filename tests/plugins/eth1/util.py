import requests_mock

from teatime import Issue


def mocked_execute(target, rpc_result, plugin, context, rpc_method, skipped=False):
    with requests_mock.Mocker() as mock:
        mock.request(
            requests_mock.ANY,
            target,
            json=rpc_result,
        )
        plugin.run(context=context)
    if not skipped:
        assert mock.called
        assert mock.request_history[0].json()["method"] == rpc_method


def assert_report_has_issue(report, meta_name, title, description, rpc_raw, severity):
    assert len(report.issues) == 1
    assert report.meta == {meta_name: True}
    issue: Issue = report.issues[0]
    assert issue.id and isinstance(issue.id, str)
    assert issue.title == title
    assert issue.description == description
    assert issue.raw_data == rpc_raw
    assert issue.severity == severity


def assert_empty_report(report, meta_name):
    assert report.issues == []
    assert report.meta == {meta_name: True}
