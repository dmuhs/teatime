import requests_mock

from teatime import Issue


def assert_mocked_execute(
    target,
    rpc_results,
    plugin,
    context,
    rpc_methods,
    skipped=False,
):
    with requests_mock.Mocker() as mock:
        mock.request(
            method=requests_mock.ANY,
            url=requests_mock.ANY,
            response_list=rpc_results,
        )
        plugin.run(context=context)
    if skipped:
        assert mock.called is False
    else:
        assert mock.call_count == len(rpc_results)
        for i, response in enumerate(rpc_results):
            assert mock.request_history[i].json()["method"] == rpc_methods[i]


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
