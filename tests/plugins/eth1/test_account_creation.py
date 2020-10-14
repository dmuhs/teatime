import pytest

from teatime import Context, NodeType, Report, Severity
from teatime.plugins.eth1 import AccountCreation

from .util import assert_empty_report, assert_mocked_execute, assert_report_has_issue

TARGET = "127.0.0.1:8545"
RPC_METHOD = "personal_newAccount"
RPC_RESULT = {"id": 1, "jsonrpc": "2.0", "result": "0xlolthisistotallyvalid"}
TEST_PASSWORD = "pa$$w0rd"
TITLE = "We managed to create a new account on your node"
DESCR = (
    "A new account can be generated on the node "
    "itself using the personal_newAccount RPC call."
)
SEVERITY = Severity.MEDIUM


@pytest.mark.parametrize(
    "plugin,node_type,rpc_results",
    (
        pytest.param(
            AccountCreation(test_password=TEST_PASSWORD),
            NodeType.GETH,
            ({"status_code": 200, "json": RPC_RESULT},),
            id="geth",
        ),
        pytest.param(
            AccountCreation(test_password=TEST_PASSWORD),
            NodeType.PARITY,
            ({"status_code": 200, "json": RPC_RESULT},),
            id="parity",
        ),
    ),
)
def test_issue_found(plugin, node_type, rpc_results):
    context = Context(
        target=TARGET, report=Report(target=TARGET, issues=[]), node_type=node_type
    )
    assert_mocked_execute(
        target=TARGET,
        rpc_results=rpc_results,
        plugin=plugin,
        context=context,
        rpc_methods=[RPC_METHOD],
    )
    assert_report_has_issue(
        report=context.report,
        meta_name=plugin.__class__.__name__,
        title=TITLE,
        description=DESCR,
        rpc_raw=RPC_RESULT["result"],
        severity=SEVERITY,
    )


@pytest.mark.parametrize(
    "plugin,node_type,rpc_results",
    (
        pytest.param(
            AccountCreation(test_password=TEST_PASSWORD),
            NodeType.GETH,
            (
                {
                    "status_code": 200,
                    "json": {},
                },
            ),
            id="geth missing payload",
        ),
        pytest.param(
            AccountCreation(test_password=TEST_PASSWORD),
            NodeType.PARITY,
            (
                {
                    "status_code": 200,
                    "json": {},
                },
            ),
            id="parity missing payload",
        ),
        pytest.param(
            AccountCreation(test_password=TEST_PASSWORD),
            NodeType.GETH,
            ({"status_code": 200, "json": {"id": 1, "jsonrpc": "2.0", "error": {}}},),
            id="geth error present",
        ),
        pytest.param(
            AccountCreation(test_password=TEST_PASSWORD),
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
    )
    assert_empty_report(report=context.report, meta_name=plugin.__class__.__name__)
