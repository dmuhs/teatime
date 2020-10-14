import pytest

from teatime import Context, NodeType, Report, Severity
from teatime.plugins.eth1 import GethAccountImport

from .util import assert_empty_report, assert_mocked_execute, assert_report_has_issue

TARGET = "127.0.0.1:8545"
RPC_METHOD = "personal_importRawKey"
TEST_PK = "0x0"
RPC_RESULT = {"id": 1, "jsonrpc": "2.0", "result": "0xlolthisistotallyvalid"}
TEST_PASSWORD = "pa$$w0rd"
TITLE = "We managed to import an account on your node"
DESCR = (
    "A private key can be imported on the node to initialize an "
    "account using the personal_importRawKey RPC call."
)
SEVERITY = Severity.MEDIUM


@pytest.mark.parametrize(
    "plugin,node_type,rpc_results",
    (
        pytest.param(
            GethAccountImport(keydata=TEST_PK, password=TEST_PASSWORD),
            NodeType.GETH,
            ({"status_code": 200, "json": RPC_RESULT},),
            id="geth",
        ),
        pytest.param(
            GethAccountImport(keydata=TEST_PK, password=TEST_PASSWORD),
            NodeType.PARITY,
            ({"status_code": 200, "json": RPC_RESULT},),
            id="parity",
        ),
    ),
)
def test_issue_found(plugin, node_type, rpc_results):
    skipped = node_type == NodeType.PARITY
    context = Context(
        target=TARGET, report=Report(target=TARGET, issues=[]), node_type=node_type
    )
    assert_mocked_execute(
        target=TARGET,
        rpc_results=rpc_results,
        plugin=plugin,
        context=context,
        rpc_methods=[RPC_METHOD],
        skipped=skipped,
    )
    if not skipped:
        assert_report_has_issue(
            report=context.report,
            meta_name=plugin.__class__.__name__,
            title=TITLE,
            description=DESCR,
            rpc_raw=RPC_RESULT["result"],
            severity=SEVERITY,
        )
    else:
        assert_empty_report(report=context.report, meta_name=plugin.__class__.__name__)


@pytest.mark.parametrize(
    "plugin,node_type,rpc_results",
    (
        pytest.param(
            GethAccountImport(keydata=TEST_PK, password=TEST_PASSWORD),
            NodeType.GETH,
            ({"status_code": 200, "json": {}},),
            id="geth missing payload",
        ),
        pytest.param(
            GethAccountImport(keydata=TEST_PK, password=TEST_PASSWORD),
            NodeType.PARITY,
            ({"status_code": 200, "json": {}},),
            id="parity missing payload",
        ),
        pytest.param(
            GethAccountImport(keydata=TEST_PK, password=TEST_PASSWORD),
            NodeType.GETH,
            ({"status_code": 200, "json": {"id": 1, "jsonrpc": "2.0", "error": {}}},),
            id="geth error present",
        ),
        pytest.param(
            GethAccountImport(keydata=TEST_PK, password=TEST_PASSWORD),
            NodeType.PARITY,
            ({"status_code": 200, "json": {"id": 1, "jsonrpc": "2.0", "error": {}}},),
            id="parity error present",
        ),
    ),
)
def test_no_issue_found(plugin, node_type, rpc_results):
    context = Context(
        target=TARGET, report=Report(target=TARGET, issues=[]), node_type=node_type
    )
    assert_mocked_execute(
        target=TARGET,
        rpc_results=rpc_results,
        plugin=plugin,
        context=context,
        rpc_methods=[RPC_METHOD],
        skipped=node_type == NodeType.PARITY,
    )
    assert_empty_report(report=context.report, meta_name=plugin.__class__.__name__)
