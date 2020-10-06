from unittest.mock import MagicMock, patch

import pytest

from teatime import NodeType, Scanner


@pytest.mark.parametrize("node_type", [NodeType.GETH, NodeType.PARITY])
def test_scanner_report(node_type: NodeType):
    mock_plugins = [MagicMock() for _ in range(5)]
    scanner = Scanner(
        ip="127.0.0.1", port=8545, node_type=node_type, plugins=mock_plugins
    )
    report = scanner.run()

    assert scanner.plugins == mock_plugins
    assert scanner.node_type == node_type
    assert scanner.target == "http://127.0.0.1:8545"

    assert report.target == scanner.target
    assert isinstance(report.meta.get("elapsed"), float)
    assert isinstance(report.id, str)
    assert isinstance(report.timestamp, str)
    assert report.issues == []

    for plugin in mock_plugins:
        plugin.run.assert_called_once()


@pytest.mark.parametrize("node_type", [NodeType.GETH, NodeType.PARITY])
@patch("teatime.scanner.scanner.logger")
def test_intrusive_logging(logger_mock, node_type: NodeType):
    plugin_mock = MagicMock()
    plugin_mock.INTRUSIVE = True
    scanner = Scanner(
        ip="127.0.0.1", port=8545, node_type=node_type, plugins=[plugin_mock]
    )
    scanner.run()
    logger_mock.warning.assert_called_once()
