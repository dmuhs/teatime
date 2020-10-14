import pytest

from teatime import Context, NodeType, Report, Severity
from teatime.plugins.eth1 import AccountUnlock

from .util import assert_empty_report, assert_mocked_execute, assert_report_has_issue

TARGET = "127.0.0.1:8545"
RPC_METHOD_UNLOCK = "personal_unlockAccount"
RPC_METHOD_ACCOUNTS = "eth_accounts"
RPC_METHOD_BALANCE = "eth_getBalance"
TEST_ADDR = "0x06012c8cf97bead5deae237070f9587f8e7a266d"
WORDLIST = ["test-password"]
RPC_RESULT_SUCCESS = {"jsonrpc": "2.0", "id": 1, "result": True}
RPC_RESULT_FAILED = {"jsonrpc": "2.0", "id": 1, "result": True}
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
TITLE = "Weak password detected!"
DESCR = (
    "The account (0x06012c8cf97bead5deae237070f9587f8e7a266d) "
    "is only protected by a weak password (test-password)"
)
INFURA_URL = "https://infura"
SEVERITY = Severity.CRITICAL


@pytest.mark.parametrize(
    "plugin,node_type,rpc_results,rpc_methods",
    (
        pytest.param(
            AccountUnlock(infura_url=INFURA_URL, wordlist=WORDLIST),
            NodeType.GETH,
            (
                {"status_code": 200, "json": RPC_RESULT_ACCOUNTS},
                {"status_code": 200, "json": RPC_RESULT_BALANCE},
                {"status_code": 200, "json": RPC_RESULT_SUCCESS},
            ),
            [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE, RPC_METHOD_UNLOCK],
            id="geth success",
        ),
        pytest.param(
            AccountUnlock(infura_url=INFURA_URL, wordlist=WORDLIST),
            NodeType.PARITY,
            (
                {"status_code": 200, "json": RPC_RESULT_ACCOUNTS},
                {"status_code": 200, "json": RPC_RESULT_BALANCE},
                {"status_code": 200, "json": RPC_RESULT_SUCCESS},
            ),
            [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE, RPC_METHOD_UNLOCK],
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
        rpc_raw=RPC_RESULT_SUCCESS["result"],
        severity=SEVERITY,
    )


@pytest.mark.parametrize(
    "plugin,node_type,rpc_results,rpc_methods",
    (
        pytest.param(
            AccountUnlock(infura_url=INFURA_URL, wordlist=WORDLIST),
            NodeType.GETH,
            ({"status_code": 200, "json": {}},),
            [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE, RPC_METHOD_UNLOCK],
            id="geth accounts missing payload",
        ),
        pytest.param(
            AccountUnlock(infura_url=INFURA_URL, wordlist=WORDLIST),
            NodeType.GETH,
            ({"status_code": 200, "json": RPC_RESULT_NO_ACCOUNTS},),
            [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE, RPC_METHOD_UNLOCK],
            id="geth no accounts",
        ),
        # TODO: Enable when better infura check in place
        # pytest.param(
        #     AccountUnlock(infura_url=INFURA_URL, wordlist=WORDLIST, skip_below=100),
        #     NodeType.GETH,
        #     ({"status_code": 200, "json": RPC_RESULT_ACCOUNTS},{"status_code": 200, "json": {}},),
        #     [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE, RPC_METHOD_UNLOCK],
        #     id="geth infura balance error",
        # ),
        pytest.param(
            AccountUnlock(infura_url=INFURA_URL, wordlist=WORDLIST, skip_below=100),
            NodeType.GETH,
            (
                {"status_code": 200, "json": RPC_RESULT_ACCOUNTS},
                {"status_code": 200, "json": RPC_RESULT_BALANCE},
            ),
            [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE, RPC_METHOD_UNLOCK],
            id="geth too little balance",
        ),
        pytest.param(
            AccountUnlock(infura_url=INFURA_URL, wordlist=WORDLIST),
            NodeType.GETH,
            (
                {"status_code": 200, "json": RPC_RESULT_ACCOUNTS},
                {"status_code": 200, "json": RPC_RESULT_BALANCE},
                {"status_code": 200, "json": {"id": 1, "jsonrpc": "2.0", "error": {}}},
            ),
            [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE, RPC_METHOD_UNLOCK],
            id="geth unlock missing payload",
        ),
        pytest.param(
            AccountUnlock(infura_url=INFURA_URL, wordlist=WORDLIST),
            NodeType.GETH,
            (
                {"status_code": 200, "json": RPC_RESULT_ACCOUNTS},
                {"status_code": 200, "json": RPC_RESULT_BALANCE},
                {
                    "status_code": 200,
                    "json": {
                        "id": 1,
                        "jsonrpc": "2.0",
                        "error": {"message": "Method not found"},
                    },
                },
            ),
            [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE, RPC_METHOD_UNLOCK],
            id="geth unlock not found",
        ),
        pytest.param(
            AccountUnlock(infura_url=INFURA_URL, wordlist=WORDLIST),
            NodeType.PARITY,
            ({"status_code": 200, "json": {}},),
            [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE, RPC_METHOD_UNLOCK],
            id="parity accounts missing payload",
        ),
        pytest.param(
            AccountUnlock(infura_url=INFURA_URL, wordlist=WORDLIST),
            NodeType.PARITY,
            ({"status_code": 200, "json": RPC_RESULT_NO_ACCOUNTS},),
            [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE, RPC_METHOD_UNLOCK],
            id="parity no accounts",
        ),
        # TODO: Enable when better infura check in place
        # pytest.param(
        #     AccountUnlock(infura_url=INFURA_URL, wordlist=WORDLIST, skip_below=100),
        #     NodeType.PARITY,
        #     ({"status_code": 200, "json": RPC_RESULT_ACCOUNTS}, {"status_code": 200, "json": {}},),
        #     [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE, RPC_METHOD_UNLOCK],
        #     id="parity infura balance error",
        # ),
        pytest.param(
            AccountUnlock(infura_url=INFURA_URL, wordlist=WORDLIST, skip_below=100),
            NodeType.PARITY,
            (
                {"status_code": 200, "json": RPC_RESULT_ACCOUNTS},
                {"status_code": 200, "json": RPC_RESULT_BALANCE},
            ),
            [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE, RPC_METHOD_UNLOCK],
            id="parity too little balance",
        ),
        pytest.param(
            AccountUnlock(infura_url=INFURA_URL, wordlist=WORDLIST),
            NodeType.PARITY,
            (
                {"status_code": 200, "json": RPC_RESULT_ACCOUNTS},
                {"status_code": 200, "json": RPC_RESULT_BALANCE},
                {"status_code": 200, "json": {"id": 1, "jsonrpc": "2.0", "error": {}}},
            ),
            [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE, RPC_METHOD_UNLOCK],
            id="parity unlock missing payload",
        ),
        pytest.param(
            AccountUnlock(infura_url=INFURA_URL, wordlist=WORDLIST),
            NodeType.PARITY,
            (
                {"status_code": 200, "json": RPC_RESULT_ACCOUNTS},
                {"status_code": 200, "json": RPC_RESULT_BALANCE},
                {
                    "status_code": 200,
                    "json": {
                        "id": 1,
                        "jsonrpc": "2.0",
                        "error": {"message": "Method not found"},
                    },
                },
            ),
            [RPC_METHOD_ACCOUNTS, RPC_METHOD_BALANCE, RPC_METHOD_UNLOCK],
            id="parity unlock not found",
        ),
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
