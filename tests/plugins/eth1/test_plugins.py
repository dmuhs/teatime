import json
import uuid
from unittest.mock import Mock, patch

import pytest
import requests_mock

from teatime import Context, Issue, NodeType, Report, Severity
from teatime.plugins.eth1 import (
    AccountCreation,
    AccountUnlock,
    GethAccountImport,
    GethDatadir,
    GethNodeInfo,
    OpenAccounts,
    ParityDevLogs,
)

TARGET = "127.0.0.1:8545"
TEST_UUID = "e7a657e4-0691-477c-b840-5fce5930fb21"
TESTCASES = []

# AccountCreation
TESTCASES += [
    pytest.param(
        AccountCreation(test_password="pa$$w0rd"),
        NodeType.PARITY,
        (
            {
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": "0xlolthisistotallyvalid",
                },
            },
        ),
        ["personal_newAccount"],
        [
            Issue(
                uuid=TEST_UUID,
                title="We managed to create a new account on your node",
                description=(
                    "A new account can be generated on the node "
                    "itself using the personal_newAccount RPC call."
                ),
                severity=Severity.MEDIUM,
                raw_data="0xlolthisistotallyvalid",
            )
        ],
        id="AccountCreation parity issue logged",
    ),
    pytest.param(
        AccountCreation(test_password="pa$$w0rd"),
        NodeType.GETH,
        (
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": "0xlolthisistotallyvalid",
                },
            },
        ),
        ["personal_newAccount"],
        [
            Issue(
                uuid=TEST_UUID,
                title="We managed to create a new account on your node",
                description=(
                    "A new account can be generated on the node "
                    "itself using the personal_newAccount RPC call."
                ),
                severity=Severity.MEDIUM,
                raw_data="0xlolthisistotallyvalid",
            )
        ],
        id="AccountCreation geth issue logged",
    ),
    pytest.param(
        AccountCreation(test_password="pa$$w0rd"),
        NodeType.GETH,
        ({"status_code": 200, "json": {"id": 1, "jsonrpc": "2.0", "error": {}}},),
        ["personal_newAccount"],
        [],
        id="AccountCreation geth error present",
    ),
    pytest.param(
        AccountCreation(test_password="pa$$w0rd"),
        NodeType.PARITY,
        ({"status_code": 200, "json": {"id": 1, "jsonrpc": "2.0", "error": {}}},),
        ["personal_newAccount"],
        [],
        id="AccountCreation parity error present",
    ),
]

# GethDatadir
TESTCASES += [
    pytest.param(
        GethDatadir(),
        NodeType.GETH,
        (
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "error": {"message": "Method not found"},
                },
            },
        ),
        ["admin_datadir"],
        [],
        id="GethDatadir geth unknown method",
    ),
    pytest.param(
        GethDatadir(),
        NodeType.GETH,
        (
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": "/home/ethismoney/.ethereum",
                },
            },
        ),
        ["admin_datadir"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Admin datadir access",
                description=(
                    "The datadir directory path can be "
                    "fetched using the admin_datadir RPC call."
                ),
                severity=Severity.LOW,
                raw_data="/home/ethismoney/.ethereum",
            )
        ],
        id="GethDatadir geth issue logged",
    ),
    pytest.param(
        GethDatadir(),
        NodeType.PARITY,
        [],
        [],
        [],
        id="GethDatadir parity skipped",
    ),
]

# GethAccountImport
TESTCASES += [
    pytest.param(
        GethAccountImport(keydata="0x0", password="pa$$w0rd"),
        NodeType.GETH,
        (
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": "0xlolthisistotallyvalid",
                },
            },
        ),
        ["personal_importRawKey"],
        [
            Issue(
                uuid=TEST_UUID,
                title="We managed to import an account on your node",
                description=(
                    "A private key can be imported on the node to initialize an "
                    "account using the personal_importRawKey RPC call."
                ),
                severity=Severity.MEDIUM,
                raw_data="0xlolthisistotallyvalid",
            )
        ],
        id="GethAccountImport geth issue logged",
    ),
    pytest.param(
        GethAccountImport(keydata="0x0", password="pa$$w0rd"),
        NodeType.PARITY,
        [],
        [],
        [],
        id="GethAccountImport parity skipped",
    ),
    pytest.param(
        GethAccountImport(keydata="0x0", password="pa$$w0rd"),
        NodeType.GETH,
        ({"status_code": 200, "json": {"id": 1, "jsonrpc": "2.0", "error": {}}},),
        ["personal_importRawKey"],
        [],
        id="GethAccountImport geth error present",
    ),
]

# AccountUnlock
TESTCASES += [
    pytest.param(
        AccountUnlock(infura_url="https://infura", wordlist=["test-password"]),
        NodeType.GETH,
        (
            {
                "status_code": 200,
                "json": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": ["0x06012c8cf97bead5deae237070f9587f8e7a266d"],
                },
            },
            {
                "status_code": 200,
                "json": {"id": 1, "jsonrpc": "2.0", "result": "0x1"},
            },
            {
                "status_code": 200,
                "json": {"jsonrpc": "2.0", "id": 1, "result": True},
            },
        ),
        ["eth_accounts", "eth_getBalance", "personal_unlockAccount"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Weak password detected!",
                description=(
                    "The account (0x06012c8cf97bead5deae237070f9587f8e7a266d) "
                    "is only protected by a weak password (test-password)"
                ),
                severity=Severity.CRITICAL,
                raw_data=True,
            )
        ],
        id="AccountUnlock geth issue logged",
    ),
    pytest.param(
        AccountUnlock(infura_url="https://infura", wordlist=["test-password"]),
        NodeType.PARITY,
        (
            {
                "status_code": 200,
                "json": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": ["0x06012c8cf97bead5deae237070f9587f8e7a266d"],
                },
            },
            {
                "status_code": 200,
                "json": {"id": 1, "jsonrpc": "2.0", "result": "0x1"},
            },
            {
                "status_code": 200,
                "json": {"jsonrpc": "2.0", "id": 1, "result": True},
            },
        ),
        ["eth_accounts", "eth_getBalance", "personal_unlockAccount"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Weak password detected!",
                description=(
                    "The account (0x06012c8cf97bead5deae237070f9587f8e7a266d) "
                    "is only protected by a weak password (test-password)"
                ),
                severity=Severity.CRITICAL,
                raw_data=True,
            )
        ],
        id="AccountUnlock parity issue logged",
    ),
    pytest.param(
        AccountUnlock(infura_url="https://infura", wordlist=["test-password"]),
        NodeType.GETH,
        (
            {
                "status_code": 200,
                "json": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": [],
                },
            },
        ),
        ["eth_accounts", "eth_getBalance", "personal_unlockAccount"],
        [],
        id="AccountUnlock geth no accounts",
    ),
    # TODO: Enable when better infura check in place
    # pytest.param(
    #     AccountUnlock(infura_url="https://infura", wordlist=["test-password"], skip_below=100),
    #     NodeType.GETH,
    #     ({"status_code": 200, "json": {
    #     "jsonrpc": "2.0",
    #     "id": 1,
    #     "result": ["0x06012c8cf97bead5deae237070f9587f8e7a266d"],
    # }},{"status_code": 200, "json": {}},),
    #     ["eth_accounts", "eth_getBalance", "personal_unlockAccount"],
    #     [],
    #     id="AccountUnlock geth infura balance error",
    # ),
    pytest.param(
        AccountUnlock(
            infura_url="https://infura", wordlist=["test-password"], skip_below=100
        ),
        NodeType.GETH,
        (
            {
                "status_code": 200,
                "json": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": ["0x06012c8cf97bead5deae237070f9587f8e7a266d"],
                },
            },
            {
                "status_code": 200,
                "json": {"id": 1, "jsonrpc": "2.0", "result": "0x1"},
            },
        ),
        ["eth_accounts", "eth_getBalance", "personal_unlockAccount"],
        [],
        id="AccountUnlock geth too little balance",
    ),
    pytest.param(
        AccountUnlock(infura_url="https://infura", wordlist=["test-password"]),
        NodeType.GETH,
        (
            {
                "status_code": 200,
                "json": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": ["0x06012c8cf97bead5deae237070f9587f8e7a266d"],
                },
            },
            {
                "status_code": 200,
                "json": {"id": 1, "jsonrpc": "2.0", "result": "0x1"},
            },
            {"status_code": 200, "json": {"id": 1, "jsonrpc": "2.0", "error": {}}},
        ),
        ["eth_accounts", "eth_getBalance", "personal_unlockAccount"],
        [],
        id="AccountUnlock geth unlock error",
    ),
    pytest.param(
        AccountUnlock(infura_url="https://infura", wordlist=["test-password"]),
        NodeType.GETH,
        (
            {
                "status_code": 200,
                "json": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": ["0x06012c8cf97bead5deae237070f9587f8e7a266d"],
                },
            },
            {
                "status_code": 200,
                "json": {"id": 1, "jsonrpc": "2.0", "result": "0x1"},
            },
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "error": {"message": "Method not found"},
                },
            },
        ),
        ["eth_accounts", "eth_getBalance", "personal_unlockAccount"],
        [],
        id="AccountUnlock geth unlock not found",
    ),
    pytest.param(
        AccountUnlock(infura_url="https://infura", wordlist=["test-password"]),
        NodeType.PARITY,
        (
            {
                "status_code": 200,
                "json": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": [],
                },
            },
        ),
        ["eth_accounts", "eth_getBalance", "personal_unlockAccount"],
        [],
        id="AccountUnlock parity no accounts",
    ),
    # TODO: Enable when better infura check in place
    # pytest.param(
    #     AccountUnlock(infura_url="https://infura", wordlist=["test-password"], skip_below=100),
    #     NodeType.PARITY,
    #     ({"status_code": 200, "json": {
    #     "jsonrpc": "2.0",
    #     "id": 1,
    #     "result": [TEST_ADDR],
    # }}, {"status_code": 200, "json": {}},),
    #     ["eth_accounts", "eth_getBalance", "personal_unlockAccount"],
    #     [],
    #     id="AccountUnlock parity infura balance error",
    # ),
    pytest.param(
        AccountUnlock(
            infura_url="https://infura", wordlist=["test-password"], skip_below=100
        ),
        NodeType.PARITY,
        (
            {
                "status_code": 200,
                "json": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": ["0x06012c8cf97bead5deae237070f9587f8e7a266d"],
                },
            },
            {
                "status_code": 200,
                "json": {"id": 1, "jsonrpc": "2.0", "result": "0x1"},
            },
        ),
        ["eth_accounts", "eth_getBalance", "personal_unlockAccount"],
        [],
        id="AccountUnlock parity too little balance",
    ),
    pytest.param(
        AccountUnlock(infura_url="https://infura", wordlist=["test-password"]),
        NodeType.PARITY,
        (
            {
                "status_code": 200,
                "json": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": ["0x06012c8cf97bead5deae237070f9587f8e7a266d"],
                },
            },
            {
                "status_code": 200,
                "json": {"id": 1, "jsonrpc": "2.0", "result": "0x1"},
            },
            {"status_code": 200, "json": {"id": 1, "jsonrpc": "2.0", "error": {}}},
        ),
        ["eth_accounts", "eth_getBalance", "personal_unlockAccount"],
        [],
        id="AccountUnlock parity unlock error",
    ),
    pytest.param(
        AccountUnlock(infura_url="https://infura", wordlist=["test-password"]),
        NodeType.PARITY,
        (
            {
                "status_code": 200,
                "json": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": ["0x06012c8cf97bead5deae237070f9587f8e7a266d"],
                },
            },
            {
                "status_code": 200,
                "json": {"id": 1, "jsonrpc": "2.0", "result": "0x1"},
            },
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "error": {"message": "Method not found"},
                },
            },
        ),
        ["eth_accounts", "eth_getBalance", "personal_unlockAccount"],
        [],
        id="AccountUnlock parity unlock not found",
    ),
]

# OpenAccounts
TESTCASES += [
    pytest.param(
        OpenAccounts(infura_url="https://infura"),
        NodeType.GETH,
        (
            {
                "status_code": 200,
                "json": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": ["0x06012c8cf97bead5deae237070f9587f8e7a266d"],
                },
            },
            {"status_code": 200, "json": {"id": 1, "jsonrpc": "2.0", "result": "0x1"}},
        ),
        ["eth_accounts", "eth_getBalance"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Found account",
                description="Account: 0x06012c8cf97bead5deae237070f9587f8e7a266d Balance: 1",
                severity=Severity.MEDIUM,
                raw_data="0x06012c8cf97bead5deae237070f9587f8e7a266d",
            )
        ],
        id="OpenAccounts geth issue logged",
    ),
    pytest.param(
        OpenAccounts(infura_url="https://infura"),
        NodeType.PARITY,
        (
            {
                "status_code": 200,
                "json": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": ["0x06012c8cf97bead5deae237070f9587f8e7a266d"],
                },
            },
            {"status_code": 200, "json": {"id": 1, "jsonrpc": "2.0", "result": "0x1"}},
        ),
        ["eth_accounts", "eth_getBalance"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Found account",
                description="Account: 0x06012c8cf97bead5deae237070f9587f8e7a266d Balance: 1",
                severity=Severity.MEDIUM,
                raw_data="0x06012c8cf97bead5deae237070f9587f8e7a266d",
            )
        ],
        id="OpenAccounts parity issue logged",
    ),
    pytest.param(
        OpenAccounts(infura_url="https://infura"),
        NodeType.GETH,
        (
            {
                "status_code": 200,
                "json": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": [],
                },
            },
        ),
        ["eth_accounts"],
        [],
        id="OpenAccounts geth no accounts",
    ),
    # TODO: test error in infura
    # pytest.param(
    #     OpenAccounts(infura_url="https://infura"),
    #     NodeType.GETH,
    #     (
    #         {"status_code": 200, "json": {
    #             "jsonrpc": "2.0",
    #             "id": 1,
    #             "result": ["0x06012c8cf97bead5deae237070f9587f8e7a266d"],
    #         }},
    #         {
    #             "status_code": 200,
    #             "json": {
    #                 "id": 1,
    #                 "jsonrpc": "2.0",
    #                 "error": {"message": "Method not found"},
    #             },
    #         },
    #     ),
    #     ["eth_accounts", "eth_getBalance"],
    # [],
    #     id="OpenAccounts geth accounts not found",
    # ),
    pytest.param(
        OpenAccounts(infura_url="https://infura"),
        NodeType.PARITY,
        (
            {
                "status_code": 200,
                "json": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": [],
                },
            },
        ),
        ["eth_accounts"],
        [],
        id="OpenAccounts parity no accounts",
    ),
    # TODO: test error in infura
    # pytest.param(
    #     OpenAccounts(infura_url="https://infura"),
    #     NodeType.PARITY,
    #     (
    #         {"status_code": 200, "json": {
    #         "jsonrpc": "2.0",
    #         "id": 1,
    #         "result": ["0x06012c8cf97bead5deae237070f9587f8e7a266d"],
    #     }},
    #         {
    #             "status_code": 200,
    #             "json": {
    #                 "id": 1,
    #                 "jsonrpc": "2.0",
    #                 "error": {"message": "Method not found"},
    #             },
    #         },
    #     ),
    #     ["eth_accounts", "eth_getBalance"],
    # [],
    #     id="OpenAccounts parity accounts not found",
    # ),
]

# GethNodeInfo
TESTCASES += [
    pytest.param(
        GethNodeInfo(),
        NodeType.GETH,
        (
            {
                "status_code": 200,
                "json": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "important": "stuff",
                    },
                },
            },
        ),
        ["admin_nodeInfo"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Admin Node Info Leaks",
                description="Admin-only information can be fetched using the admin_nodeInfo RPC call.",
                severity=Severity.LOW,
                raw_data={"important": "stuff"},
            )
        ],
        id="GethNodeInfo issue logged",
    ),
    pytest.param(
        GethNodeInfo(),
        NodeType.PARITY,
        [],
        [],
        [],
        id="GethNodeInfo parity skipped",
    ),
]

# ParityDevLogs
TESTCASES += [
    pytest.param(
        ParityDevLogs(),
        NodeType.GETH,
        [],
        [],
        [],
        id="ParityDevLogs geth skipped",
    ),
    pytest.param(
        ParityDevLogs(),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "error": {"message": "Method not found"},
                },
            }
        ],
        ["parity_devLogs"],
        [],
        id="ParityDevLogs error skipped",
    ),
    pytest.param(
        ParityDevLogs(),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {"id": 1, "jsonrpc": "2.0", "result": ["important log stuff"]},
            }
        ],
        ["parity_devLogs"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Developer log information leak",
                description="The node's developer logs can be fetched using the parity_devLogs RPC call.",
                severity=Severity.CRITICAL,
                raw_data=["important log stuff"],
            )
        ],
        id="ParityDevLogs geth skipped",
    ),
]


@pytest.mark.parametrize(
    "plugin,node_type,rpc_results,rpc_methods,issues",
    TESTCASES,
)
@patch(
    target="teatime.reporting.issue.uuid4",
    new=Mock(return_value=uuid.UUID(TEST_UUID)),
)
def test_issues(plugin, node_type, rpc_results, rpc_methods, issues):
    context = Context(
        target=TARGET,
        report=Report(uuid=TEST_UUID, target=TARGET, issues=[]),
        node_type=node_type,
    )
    with requests_mock.Mocker() as mock:
        mock.request(
            method=requests_mock.ANY,
            url=requests_mock.ANY,
            response_list=rpc_results,
        )
        plugin.run(context=context)

    assert mock.call_count == len(rpc_results)
    for i, response in enumerate(rpc_results):
        assert mock.request_history[i].json()["method"] == rpc_methods[i]

    assert context.report.meta == {plugin.__class__.__name__: True}
    for i1, i2 in zip(context.report.issues, issues):
        # compare dict representations here for more verbose failure diffs
        assert i1.to_dict() == i2.to_dict()
