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
    HashrateStatus,
    MiningStatus,
    NetworkListening,
    OpenAccounts,
    ParityChangeCoinbase,
    ParityChangeExtra,
    ParityChangeTarget,
    ParityDevLogs,
    ParityGasCeiling,
    ParityGasFloor,
    ParitySyncMode,
    PeerCountStatus,
    PeerlistLeak,
    PeerlistManipulation,
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
                description="Admin-only information can be fetched using the admin_nodeInfo RPC "
                "call.",
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
                description="The node's developer logs can be fetched using the parity_devLogs "
                "RPC call.",
                severity=Severity.CRITICAL,
                raw_data=["important log stuff"],
            )
        ],
        id="ParityDevLogs geth skipped",
    ),
]

# PeerlistLeak
TESTCASES += [
    pytest.param(
        PeerlistLeak(),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {"id": 1, "jsonrpc": "2.0", "result": "peer stuff"},
            }
        ],
        ["parity_netPeers"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Peer list information leak",
                description="Admin-only peer list information can be fetched with the "
                "parity_netPeers RPC call.",
                severity=Severity.MEDIUM,
                raw_data="peer stuff",
            )
        ],
        id="PeerlistLeak parity issue logged",
    ),
    pytest.param(
        PeerlistLeak(),
        NodeType.GETH,
        [
            {
                "status_code": 200,
                "json": {"id": 1, "jsonrpc": "2.0", "result": "peer stuff"},
            }
        ],
        ["admin_peers"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Admin Peerlist Access",
                description="Admin-only information about the peer list can be fetched using the "
                "admin_peers RPC call.",
                severity=Severity.MEDIUM,
                raw_data="peer stuff",
            )
        ],
        id="PeerlistLeak geth issue logged",
    ),
    pytest.param(
        PeerlistLeak(),
        NodeType.GETH,
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
        ["admin_peers"],
        [],
        id="PeerlistLeak geth error",
    ),
    pytest.param(
        PeerlistLeak(),
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
        ["parity_netPeers"],
        [],
        id="PeerlistLeak parity error",
    ),
]

# ParityGasCeiling
TESTCASES += [
    pytest.param(
        ParityGasCeiling(gas_target=1000),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {"id": 1, "jsonrpc": "2.0", "result": True},
            }
        ],
        ["parity_setGasCeilTarget"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Gas ceiling target can be changed",
                description="Anyone can change the gas ceiling value using the "
                "parity_setGasCeilTarget RPC call.",
                severity=Severity.CRITICAL,
                raw_data=True,
            )
        ],
        id="ParityGasCeiling parity issue logged",
    ),
    pytest.param(
        ParityGasCeiling(gas_target=1000),
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
        ["parity_setGasCeilTarget"],
        [],
        id="ParityGasCeiling parity error",
    ),
    pytest.param(
        ParityGasCeiling(gas_target=1000),
        NodeType.GETH,
        [],
        [],
        [],
        id="ParityGasCeiling geth skipped",
    ),
]

# ParityGasFloor
TESTCASES += [
    pytest.param(
        ParityGasFloor(gas_floor=1000),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {"id": 1, "jsonrpc": "2.0", "result": True},
            }
        ],
        ["parity_setGasFloorTarget"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Gas floor target can be changed",
                description="Anyone can change the gas floor value using the "
                "parity_setGasFloorTarget RPC call.",
                severity=Severity.CRITICAL,
                raw_data=True,
            )
        ],
        id="ParityGasFloor parity issue logged",
    ),
    pytest.param(
        ParityGasFloor(gas_floor=1000),
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
        ["parity_setGasFloorTarget"],
        [],
        id="ParityGasFloor parity error",
    ),
    pytest.param(
        ParityGasFloor(gas_floor=1000),
        NodeType.GETH,
        [],
        [],
        [],
        id="ParityGasFloor geth skipped",
    ),
]

# ParityChangeCoinbase
TESTCASES += [
    pytest.param(
        ParityChangeCoinbase(author="0x0"),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": True,
                },
            }
        ],
        ["parity_setAuthor"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Coinbase address change possible",
                description="Anyone can change the coinbase address and redirect miner payouts using the parity_setAuthor RPC call.",
                severity=Severity.CRITICAL,
                raw_data=True,
            )
        ],
        id="ParityChangeCoinbase parity issue logged",
    ),
    pytest.param(
        ParityChangeCoinbase(author="0x0"),
        NodeType.GETH,
        [],
        [],
        [],
        id="ParityChangeCoinbase geth skipped",
    ),
    pytest.param(
        ParityChangeCoinbase(author="0x0"),
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
        ["parity_setAuthor"],
        [],
        id="ParityChangeCoinbase parity error",
    ),
]


# ParityChangeTarget
TESTCASES += [
    pytest.param(
        ParityChangeTarget(target_chain="test"),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": True,
                },
            }
        ],
        ["parity_setChain"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Chain preset change possible",
                description="Anyone can change the node's target chain value using the parity_setChain RPC call.",
                severity=Severity.CRITICAL,
                raw_data=True,
            )
        ],
        id="ParityChangeTarget parity issue logged",
    ),
    pytest.param(
        ParityChangeTarget(target_chain="test"),
        NodeType.GETH,
        [],
        [],
        [],
        id="ParityChangeTarget geth skipped",
    ),
    pytest.param(
        ParityChangeTarget(target_chain="test"),
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
        ["parity_setChain"],
        [],
        id="ParityChangeTarget parity error",
    ),
]


# ParityChangeExtra
TESTCASES += [
    pytest.param(
        ParityChangeExtra(extra_data="pwn'd"),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": True,
                },
            }
        ],
        ["parity_setExtraData"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Extra data change possible",
                description="Anyone can change the extra data attached to newly mined blocks using the parity_setExtraData RPC call.",
                severity=Severity.LOW,
                raw_data=True,
            )
        ],
        id="ParityChangeExtra parity issue logged",
    ),
    pytest.param(
        ParityChangeExtra(extra_data="pwn'd"),
        NodeType.GETH,
        [],
        [],
        [],
        id="ParityChangeExtra geth skipped",
    ),
    pytest.param(
        ParityChangeExtra(extra_data="pwn'd"),
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
        ["parity_setExtraData"],
        [],
        id="ParityChangeExtra parity error",
    ),
]

# ParitySyncMode
TESTCASES += [
    pytest.param(
        ParitySyncMode(mode="offline"),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": True,
                },
            }
        ],
        ["parity_setMode"],
        [
            Issue(
                uuid=TEST_UUID,
                title="The sync mode can be changed",
                description="Anyone can change the node's sync mode using the parity_setMode RPC call.",
                severity=Severity.CRITICAL,
                raw_data=True,
            )
        ],
        id="ParitySyncMode parity issue logged",
    ),
    pytest.param(
        ParitySyncMode(mode="offline"),
        NodeType.GETH,
        [],
        [],
        [],
        id="ParitySyncMode geth skipped",
    ),
    pytest.param(
        ParitySyncMode(mode="offline"),
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
        ["parity_setMode"],
        [],
        id="ParitySyncMode parity error",
    ),
]

# MiningStatus
TESTCASES += [
    pytest.param(
        MiningStatus(should_mine=True),
        NodeType.GETH,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": True,
                },
            }
        ],
        ["eth_mining"],
        [],
        id="MiningStatus geth is and should be mining",
    ),
    pytest.param(
        MiningStatus(should_mine=False),
        NodeType.GETH,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": False,
                },
            }
        ],
        ["eth_mining"],
        [],
        id="MiningStatus geth is not and should not be mining",
    ),
    pytest.param(
        MiningStatus(should_mine=False),
        NodeType.GETH,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": True,
                },
            }
        ],
        ["eth_mining"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Mining Status",
                description="The node should not be mining but is",
                severity=Severity.MEDIUM,
                raw_data=True,
            )
        ],
        id="MiningStatus geth not mining but should be",
    ),
    pytest.param(
        MiningStatus(should_mine=True),
        NodeType.GETH,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": False,
                },
            }
        ],
        ["eth_mining"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Mining Status",
                description="The node should be mining but isn't",
                severity=Severity.MEDIUM,
                raw_data=False,
            )
        ],
        id="MiningStatus geth should be mining but is not",
    ),
    pytest.param(
        MiningStatus(should_mine=True),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": True,
                },
            }
        ],
        ["eth_mining"],
        [],
        id="MiningStatus parity is and should be mining",
    ),
    pytest.param(
        MiningStatus(should_mine=False),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": False,
                },
            }
        ],
        ["eth_mining"],
        [],
        id="MiningStatus parity is not and should not be mining",
    ),
    pytest.param(
        MiningStatus(should_mine=False),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": True,
                },
            }
        ],
        ["eth_mining"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Mining Status",
                description="The node should not be mining but is",
                severity=Severity.MEDIUM,
                raw_data=True,
            )
        ],
        id="MiningStatus parity not mining but should be",
    ),
    pytest.param(
        MiningStatus(should_mine=True),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": False,
                },
            }
        ],
        ["eth_mining"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Mining Status",
                description="The node should be mining but isn't",
                severity=Severity.MEDIUM,
                raw_data=False,
            )
        ],
        id="MiningStatus parity should be mining but is not",
    ),
]

# HashrateStatus
TESTCASES += [
    pytest.param(
        HashrateStatus(expected_hashrate=1000),
        NodeType.GETH,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": "0x3e8",
                },
            }
        ],
        ["eth_hashrate"],
        [],
        id="HashrateStatus geth hashrate equals",
    ),
    pytest.param(
        HashrateStatus(expected_hashrate=100),
        NodeType.GETH,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": "0x3e8",
                },
            }
        ],
        ["eth_hashrate"],
        [],
        id="HashrateStatus geth hashrate larger",
    ),
    pytest.param(
        HashrateStatus(expected_hashrate=10000),
        NodeType.GETH,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": "0x3e8",
                },
            }
        ],
        ["eth_hashrate"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Mining Hashrate Low",
                description="The hashrate should be >= 10000 but only is 1000",
                severity=Severity.MEDIUM,
                raw_data=1000,
            )
        ],
        id="HashrateStatus geth hashrate smaller",
    ),
    pytest.param(
        HashrateStatus(expected_hashrate=1000),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": "0x3e8",
                },
            }
        ],
        ["eth_hashrate"],
        [],
        id="HashrateStatus parity hashrate equals",
    ),
    pytest.param(
        HashrateStatus(expected_hashrate=100),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": "0x3e8",
                },
            }
        ],
        ["eth_hashrate"],
        [],
        id="HashrateStatus parity hashrate larger",
    ),
    pytest.param(
        HashrateStatus(expected_hashrate=10000),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": "0x3e8",
                },
            }
        ],
        ["eth_hashrate"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Mining Hashrate Low",
                description="The hashrate should be >= 10000 but only is 1000",
                severity=Severity.MEDIUM,
                raw_data=1000,
            )
        ],
        id="HashrateStatus parity hashrate smaller",
    ),
]

# NetworkListening
TESTCASES += [
    pytest.param(
        NetworkListening(),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": False,
                },
            }
        ],
        ["net_listening"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Node not listening to peers",
                description="The node is not listening to new peer requests",
                severity=Severity.HIGH,
                raw_data=False,
            )
        ],
        id="NetworkListening parity issue logged",
    ),
    pytest.param(
        NetworkListening(),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": True,
                },
            }
        ],
        ["net_listening"],
        [],
        id="NetworkListening parity no issue",
    ),
    pytest.param(
        NetworkListening(),
        NodeType.GETH,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": False,
                },
            }
        ],
        ["net_listening"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Node not listening to peers",
                description="The node is not listening to new peer requests",
                severity=Severity.HIGH,
                raw_data=False,
            )
        ],
        id="NetworkListening geth issue logged",
    ),
    pytest.param(
        NetworkListening(),
        NodeType.GETH,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": True,
                },
            }
        ],
        ["net_listening"],
        [],
        id="NetworkListening geth no issue",
    ),
]

# PeerCountStatus
TESTCASES += [
    pytest.param(
        PeerCountStatus(minimum_peercount=2),
        NodeType.GETH,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": "0x2",
                },
            }
        ],
        ["net_peerCount"],
        [],
        id="PeerCountStatus geth peer count equals",
    ),
    pytest.param(
        PeerCountStatus(minimum_peercount=1),
        NodeType.GETH,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": "0x2",
                },
            }
        ],
        ["net_peerCount"],
        [],
        id="PeerCountStatus geth peer count larger",
    ),
    pytest.param(
        PeerCountStatus(minimum_peercount=10),
        NodeType.GETH,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": "0x2",
                },
            }
        ],
        ["net_peerCount"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Number of peers too low!",
                description="Too few peers (current < minimum): 2 < 10",
                severity=Severity.MEDIUM,
                raw_data=2,
            )
        ],
        id="PeerCountStatus geth peer count smaller",
    ),
    pytest.param(
        PeerCountStatus(minimum_peercount=2),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": "0x2",
                },
            }
        ],
        ["net_peerCount"],
        [],
        id="PeerCountStatus parity peer count equals",
    ),
    pytest.param(
        PeerCountStatus(minimum_peercount=1),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": "0x2",
                },
            }
        ],
        ["net_peerCount"],
        [],
        id="PeerCountStatus parity peer count larger",
    ),
    pytest.param(
        PeerCountStatus(minimum_peercount=10),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": "0x2",
                },
            }
        ],
        ["net_peerCount"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Number of peers too low!",
                description="Too few peers (current < minimum): 2 < 10",
                severity=Severity.MEDIUM,
                raw_data=2,
            )
        ],
        id="PeerCountStatus parity peer count smaller",
    ),
]

# PeerlistManipulation
TESTCASES += [
    pytest.param(
        PeerlistManipulation(test_enode="test"),
        NodeType.GETH,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": True,
                },
            }
        ],
        ["admin_addPeer"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Peer list manipulation",
                description="Arbitrary peers can be added using the admin_addPeer RPC call.",
                severity=Severity.HIGH,
                raw_data=True,
            )
        ],
        id="PeerlistManipulation geth issue logged",
    ),
    pytest.param(
        PeerlistManipulation(test_enode="test"),
        NodeType.GETH,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": False,
                },
            }
        ],
        ["admin_addPeer"],
        [],
        id="PeerlistManipulation geth no issue",
    ),
    pytest.param(
        PeerlistManipulation(test_enode="test"),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": True,
                },
            }
        ],
        ["parity_addReservedPeer"],
        [
            Issue(
                uuid=TEST_UUID,
                title="Peer list manipulation",
                description="Reserved peers can be added to the node's peer list using the parity_addReservedPeer RPC call",
                severity=Severity.HIGH,
                raw_data=True,
            )
        ],
        id="PeerlistManipulation parity issue logged",
    ),
    pytest.param(
        PeerlistManipulation(test_enode="test"),
        NodeType.PARITY,
        [
            {
                "status_code": 200,
                "json": {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "result": False,
                },
            }
        ],
        ["parity_addReservedPeer"],
        [],
        id="PeerlistManipulation parity no issue",
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
