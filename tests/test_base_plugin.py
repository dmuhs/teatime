from unittest.mock import MagicMock

import pytest
import requests_mock
from requests.exceptions import ConnectionError, ConnectTimeout, ReadTimeout

from teatime import Context, JSONRPCPlugin, NodeType, PluginException, Report


class SampleRPCPlugin(JSONRPCPlugin):
    def _check(self, context: Context):
        pass


class IncompleteRPCPlugin(JSONRPCPlugin):
    pass


def assert_context(context: Context, target, node_type, meta):
    assert context.target == target
    assert context.node_type == node_type
    assert context.report.target == target
    assert context.report.issues == []
    assert context.report.meta == meta


def assert_report(report: Report, target, meta):
    assert isinstance(report.timestamp, str)
    assert isinstance(report.id, str)
    report_dict = report.to_dict()
    assert report_dict.get("issues") == []
    assert report_dict.get("meta") == meta
    assert isinstance(report_dict.get("timestamp"), str)
    assert report_dict.get("target") == target
    assert report_dict.get("ok") is True


def test_repr_name():
    plugin = SampleRPCPlugin()
    assert "SampleRPCPlugin" in str(plugin)


def test_run_context():
    plugin = SampleRPCPlugin()
    target = "127.0.0.1:8545"
    node_type = NodeType.GETH
    expected_meta = {"SampleRPCPlugin": True}
    context = Context(
        target=target,
        report=Report(target=target),
        node_type=node_type,
    )
    plugin._check = MagicMock()
    plugin.run(context=context)

    plugin._check.assert_called_once()
    assert plugin.INTRUSIVE is True
    assert_context(
        context=context, target=target, node_type=node_type, meta=expected_meta
    )
    assert_report(report=context.report, target=target, meta=expected_meta)


def test_run_plugin_exception():
    plugin = SampleRPCPlugin()
    target = "127.0.0.1:8545"
    node_type = NodeType.GETH
    expected_meta = {"SampleRPCPlugin": True}
    context = Context(
        target=target,
        report=Report(target=target),
        node_type=node_type,
    )
    plugin._check = MagicMock(side_effect=PluginException)
    plugin.run(context=context)

    plugin._check.assert_called_once()
    assert plugin.INTRUSIVE is True
    assert_context(
        context=context, target=target, node_type=node_type, meta=expected_meta
    )
    assert_report(report=context.report, target=target, meta=expected_meta)


def test_incomplete_plugin():
    with pytest.raises(TypeError):
        IncompleteRPCPlugin()


def test_valid_json_rpc():
    target = "http://127.0.0.1:8545"
    expected_result = "0x65a8db"
    plugin = SampleRPCPlugin()
    with requests_mock.Mocker() as mock:
        mock.request(
            requests_mock.ANY,
            target,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "result": expected_result,
            },
        )
        result = plugin.get_rpc_json(target=target, method="eth_blockNumber", params=[])
    assert result == expected_result


def test_json_rpc_connection_timeout():
    target = "http://127.0.0.1:8545"
    plugin = SampleRPCPlugin()
    with requests_mock.Mocker() as mock, pytest.raises(PluginException):
        mock.request(requests_mock.ANY, target, exc=ConnectTimeout)
        plugin.get_rpc_json(target=target, method="eth_blockNumber", params=[])


def test_json_rpc_read_timeout():
    target = "http://127.0.0.1:8545"
    plugin = SampleRPCPlugin()
    with requests_mock.Mocker() as mock, pytest.raises(PluginException):
        mock.request(requests_mock.ANY, target, exc=ReadTimeout)
        plugin.get_rpc_json(target=target, method="eth_blockNumber", params=[])


def test_json_rpc_connection_error():
    target = "http://127.0.0.1:8545"
    plugin = SampleRPCPlugin()
    with requests_mock.Mocker() as mock, pytest.raises(PluginException):
        mock.request(requests_mock.ANY, target, exc=ConnectionError)
        plugin.get_rpc_json(target=target, method="eth_blockNumber", params=[])


def test_json_rpc_non_ok():
    target = "http://127.0.0.1:8545"
    plugin = SampleRPCPlugin()
    with requests_mock.Mocker() as mock, pytest.raises(PluginException):
        mock.request(requests_mock.ANY, target, json={}, status_code=500)
        plugin.get_rpc_json(target=target, method="eth_blockNumber", params=[])


def test_json_rpc_missing_result():
    target = "http://127.0.0.1:8545"
    plugin = SampleRPCPlugin()
    with requests_mock.Mocker() as mock, pytest.raises(PluginException):
        mock.request(requests_mock.ANY, target, json={})
        plugin.get_rpc_json(target=target, method="eth_blockNumber", params=[])


def test_json_rpc_error_key():
    target = "http://127.0.0.1:8545"
    plugin = SampleRPCPlugin()
    with requests_mock.Mocker() as mock, pytest.raises(PluginException):
        mock.request(
            requests_mock.ANY,
            target,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "result": "garbage",
                "error": {"code": -32601, "message": "Method not found", "data": None},
            },
        )
        plugin.get_rpc_json(target=target, method="eth_blockNumber", params=[])


def test_json_rpc_value_error():
    target = "http://127.0.0.1:8545"
    plugin = SampleRPCPlugin()
    with requests_mock.Mocker() as mock, pytest.raises(PluginException):
        mock.request(
            requests_mock.ANY,
            target,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "result": "invalid",
            },
        )
        plugin.get_rpc_int(target=target, method="eth_blockNumber", params=[])
