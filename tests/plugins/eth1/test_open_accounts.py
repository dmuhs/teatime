import pytest

from teatime import Context, NodeType, Report, Severity
from teatime.plugins.eth1 import OpenAccounts

from .util import assert_empty_report, assert_mocked_execute, assert_report_has_issue

TARGET = "127.0.0.1:8545"
RPC_METHOD_ACCOUNTS = "eth_accounts"
RPC_METHOD_BALANCE = "eth_getBalance"
TEST_ADDR = "0x06012c8cf97bead5deae237070f9587f8e7a266d"

RPC_RESULT_ACCOUNTS = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": [TEST_ADDR],
}
RPC_RESULT_NO_ACCOUNTS = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": [],
}
RPC_RESULT_BALANCE = {"id": 1, "jsonrpc": "2.0", "result": "0x1"}
TITLE = "Found account"
DESCR = "Account: 0x06012c8cf97bead5deae237070f9587f8e7a266d Balance: 1"
INFURA_URL = "https://infura"
SEVERITY = Severity.MEDIUM


@pytest.mark.parametrize(
    "plugin,node_type,rpc_results,rpc_methods",
    (
        pytest.param(
            OpenAccounts(infura_url=INFURA_URL),
            NodeType.GETH,
            (
                {"status_code": 200, "json": RPC_RESULT_ACCOUNTS},
                {"status_code": 200, "json": RPC_RESULT_BALANCE},
            ),
            [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE],
            id="geth success",
        ),
        pytest.param(
            OpenAccounts(infura_url=INFURA_URL),
            NodeType.PARITY,
            (
                {"status_code": 200, "json": RPC_RESULT_ACCOUNTS},
                {"status_code": 200, "json": RPC_RESULT_BALANCE},
            ),
            [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE],
            id="parity success",
        ),
    ),
)
def test_issue_found(plugin, node_type, rpc_results, rpc_methods):
    context = Context(
        target=TARGET, report=Report(target=TARGET, issues=[]), node_type=node_type
    )
    assert_mocked_execute(
        target=TARGET,
        rpc_results=rpc_results,
        plugin=plugin,
        context=context,
        rpc_methods=rpc_methods,
    )
    assert_report_has_issue(
        report=context.report,
        meta_name=plugin.__class__.__name__,
        title=TITLE,
        description=DESCR,
        rpc_raw=TEST_ADDR,
        severity=SEVERITY,
    )


@pytest.mark.parametrize(
    "plugin,node_type,rpc_results,rpc_methods",
    (
        pytest.param(
            OpenAccounts(infura_url=INFURA_URL),
            NodeType.GETH,
            ({"status_code": 200, "json": {}},),
            [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE],
            id="geth accounts missing payload",
        ),
        pytest.param(
            OpenAccounts(infura_url=INFURA_URL),
            NodeType.GETH,
            ({"status_code": 200, "json": RPC_RESULT_NO_ACCOUNTS},),
            [RPC_METHOD_ACCOUNTS],
            id="geth no accounts",
        ),
        # TODO: test error in infura
        # pytest.param(
        #     OpenAccounts(infura_url=INFURA_URL),
        #     NodeType.GETH,
        #     (
        #         {"status_code": 200, "json": RPC_RESULT_ACCOUNTS},
        #         {
        #             "status_code": 200,
        #             "json": {
        #                 "id": 1,
        #                 "jsonrpc": "2.0",
        #                 "error": {"message": "Method not found"},
        #             },
        #         },
        #     ),
        #     [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE],
        #     id="geth accounts not found",
        # ),
        pytest.param(
            OpenAccounts(infura_url=INFURA_URL),
            NodeType.PARITY,
            ({"status_code": 200, "json": {}},),
            [RPC_METHOD_ACCOUNTS],
            id="parity accounts missing payload",
        ),
        pytest.param(
            OpenAccounts(infura_url=INFURA_URL),
            NodeType.PARITY,
            ({"status_code": 200, "json": RPC_RESULT_NO_ACCOUNTS},),
            [RPC_METHOD_ACCOUNTS],
            id="parity no accounts",
        ),
        # TODO: test error in infura
        # pytest.param(
        #     OpenAccounts(infura_url=INFURA_URL),
        #     NodeType.PARITY,
        #     (
        #         {"status_code": 200, "json": RPC_RESULT_ACCOUNTS},
        #         {
        #             "status_code": 200,
        #             "json": {
        #                 "id": 1,
        #                 "jsonrpc": "2.0",
        #                 "error": {"message": "Method not found"},
        #             },
        #         },
        #     ),
        #     [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE],
        #     id="parity accounts not found",
        # ),
    ),
)
def test_no_issue_found(plugin, node_type, rpc_results, rpc_methods):
    context = Context(
        target=TARGET, report=Report(target=TARGET, issues=[]), node_type=node_type
    )
    assert_mocked_execute(
        target=TARGET,
        rpc_results=rpc_results,
        plugin=plugin,
        context=context,
        rpc_methods=rpc_methods,
    )
    assert_empty_report(report=context.report, meta_name=plugin.__class__.__name__)
