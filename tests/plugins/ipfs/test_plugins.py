import uuid
from unittest.mock import Mock, patch

import pytest
import requests_mock

from teatime import Context, Issue, NodeType, PluginException, Report, Severity
from teatime.plugins.ipfs import (
    AddPin,
    ChangeLogLevel,
    CIDFSEnum,
    CommandCheck,
    DependencyVersion,
    EnumerateLogs,
    EnumeratePins,
    FilestoreEnum,
    KeyLeaks,
    OpenUploadAdd,
    OpenUploadTarAdd,
    P2PCloseStream,
    P2PCreateListener,
    P2PEnableForwarding,
    P2PListListeners,
    P2PListStreams,
    P2PStopForwarding,
    ReadLogs,
    RemovePin,
    Shutdown,
    UnixFSEnum,
    Version,
    WebUIEnabled,
)

TARGET = "127.0.0.1:8545"
TEST_UUID = "e7a657e4-0691-477c-b840-5fce5930fb21"
TESTCASES = []


# Shutdown
TESTCASES += [
    pytest.param(
        Shutdown(),
        NodeType.IPFS,
        ({"text": ""},),
        "/api/v0/shutdown",
        [
            Issue(
                uuid=TEST_UUID,
                title="Exposed Shutdown Endpoint",
                description=(
                    "Anyone can shut down the IPFS daemon. This plugin has shut down the node. "
                    "This is the highest possible threat to availability."
                ),
                severity=Severity.CRITICAL,
                raw_data="",
            )
        ],
        id="Shutdown success issue logged",
    ),
    pytest.param(
        Shutdown(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/shutdown",
        [],
        id="Shutdown failed no issue logged",
    ),
    pytest.param(
        Shutdown(),
        NodeType.GETH,
        [],
        "/api/v0/shutdown",
        [],
        id="Shutdown bad node no issue logged",
    ),
]

# AddPin
TESTCASES += [
    pytest.param(
        AddPin(),
        NodeType.IPFS,
        ({"json": {"Pins": ["test"], "Progress": "test"}},),
        "/api/v0/pin/add",
        [
            Issue(
                uuid=TEST_UUID,
                title="Anyone can pin data to the node",
                description=(
                    "Open pinning can enable an attacker to flush a large amount of"
                    "random data onto the node's disk until storage space is exhausted,"
                    "thus performing a denial of service attack against future uploads/pins."
                ),
                severity=Severity.HIGH,
                raw_data='{"Pins": ["test"], "Progress": "test"}',
            )
        ],
        id="Pin add success issue logged",
    ),
    pytest.param(
        AddPin(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/pin/add",
        [],
        id="Pin add failed no issue logged",
    ),
    pytest.param(
        AddPin(),
        NodeType.GETH,
        [],
        "/api/v0/pin/add",
        [],
        id="Pin add bad node no issue logged",
    ),
]

# EnumeratePins
TESTCASES += [
    pytest.param(
        EnumeratePins(),
        NodeType.IPFS,
        (
            {
                "json": {
                    "PinLsList": {"Keys": {"<string>": {"Type": "<string>"}}},
                    "PinLsObject": {"Cid": "<string>", "Type": "<string>"},
                }
            },
        ),
        "/api/v0/pin/ls",
        [
            Issue(
                uuid=TEST_UUID,
                title="Anyone can list the node's pins",
                description=(
                    "It is possible to list all the content IDs that "
                    "are pinned to the node's local storage."
                ),
                severity=Severity.LOW,
                raw_data=(
                    '{"PinLsList": {"Keys": {"<string>": {"Type": "<string>"}}},'
                    ' "PinLsObject": {"Cid": "<string>", "Type": "<string>"}}'
                ),
            )
        ],
        id="Pin list success issue logged",
    ),
    pytest.param(
        EnumeratePins(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/pin/ls",
        [],
        id="Pin list failed no issue logged",
    ),
    pytest.param(
        EnumeratePins(),
        NodeType.GETH,
        [],
        "/api/v0/pin/ls",
        [],
        id="Pin list bad node no issue logged",
    ),
]

# RemovePin
TESTCASES += [
    pytest.param(
        RemovePin(),
        NodeType.IPFS,
        (
            {
                "json": {"Pins": ["<string>"]},
            },
            {"json": {"Pins": ["test"], "Progress": "test"}},
        ),
        "/api/v0/pin/rm",
        [
            Issue(
                uuid=TEST_UUID,
                title="Anyone can remove the node's pins",
                description=(
                    "It is possible to remove all the content IDs that "
                    "are pinned to the node's local storage. This poses "
                    "a risk to data availability as an attacker can unpin "
                    "any file."
                ),
                severity=Severity.HIGH,
                raw_data='{"Pins": ["<string>"]}',
            )
        ],
        id="Pin rm success issue logged",
    ),
    pytest.param(
        RemovePin(restore=False),
        NodeType.IPFS,
        (
            {
                "json": {"Pins": ["<string>"]},
            },
        ),
        "/api/v0/pin/rm",
        [
            Issue(
                uuid=TEST_UUID,
                title="Anyone can remove the node's pins",
                description=(
                    "It is possible to remove all the content IDs that "
                    "are pinned to the node's local storage. This poses "
                    "a risk to data availability as an attacker can unpin "
                    "any file."
                ),
                severity=Severity.HIGH,
                raw_data='{"Pins": ["<string>"]}',
            )
        ],
        id="Pin rm no restore success issue logged",
    ),
    pytest.param(
        RemovePin(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/pin/rm",
        [],
        id="Pin rm failed no issue logged",
    ),
    pytest.param(
        RemovePin(),
        NodeType.GETH,
        [],
        "/api/v0/pin/rm",
        [],
        id="Pin rm bad node no issue logged",
    ),
]


# EnumeratePins
TESTCASES += [
    pytest.param(
        WebUIEnabled(),
        NodeType.IPFS,
        ({"text": "test"},),
        "/webui",
        [
            Issue(
                uuid=TEST_UUID,
                title="Exposed Web UI",
                description=(
                    "Anyone can access the Web UI. A plethora of administrative "
                    "actions can be done through the web interface. This includes "
                    "changing the node's configuration, which can be used to open "
                    "other potential attack vectors."
                ),
                severity=Severity.HIGH,
                raw_data="127.0.0.1:8545/webui",
            )
        ],
        id="WebUI get success issue logged",
    ),
    pytest.param(
        WebUIEnabled(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/webui",
        [],
        id="WebUI get failed no issue logged",
    ),
    pytest.param(
        WebUIEnabled(),
        NodeType.GETH,
        [],
        "/webui",
        [],
        id="WebUI bad node no issue logged",
    ),
]

# Version
TESTCASES += [
    pytest.param(
        Version(),
        NodeType.IPFS,
        (
            {
                "json": {
                    "Commit": "<string>",
                    "Golang": "<string>",
                    "Repo": "<string>",
                    "System": "<string>",
                    "Version": "<string>",
                }
            },
        ),
        "/api/v0/version",
        [
            Issue(
                uuid=TEST_UUID,
                title="Version Information Leak",
                description=(
                    "Version information of the node and its execution environment is exposed. "
                    "This allows an attacker to obtain information about the system's Go version, "
                    "operating system, as well as the IPFS node's version and origin repository"
                ),
                severity=Severity.LOW,
                raw_data=(
                    '{"Commit": "<string>", "Golang": "<string>", '
                    '"Repo": "<string>", "System": "<string>", "Version": "<string>"}'
                ),
            )
        ],
        id="Version success issue logged",
    ),
    pytest.param(
        Version(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/version",
        [],
        id="Version failed no issue logged",
    ),
    pytest.param(
        Version(),
        NodeType.GETH,
        [],
        "/api/v0/version",
        [],
        id="Version bad node no issue logged",
    ),
]


# DependencyVersion
TESTCASES += [
    pytest.param(
        DependencyVersion(),
        NodeType.IPFS,
        (
            {
                "json": {
                    "Path": "<string>",
                    "Sum": "<string>",
                    "ReplacedBy": "<string>",
                    "Version": "<string>",
                }
            },
        ),
        "/api/v0/version/deps",
        [
            Issue(
                uuid=TEST_UUID,
                title="Dependency Version Information Leak",
                description=(
                    "Dependency version information is exposed. "
                    "This allows an attacker to obtain information about the system's Go version, "
                    "operating system, as well as the IPFS node's version and origin repository"
                ),
                severity=Severity.LOW,
                raw_data=(
                    '[{"Path": "<string>", "Sum": "<string>", '
                    '"ReplacedBy": "<string>", "Version": "<string>"}]'
                ),
            ),
            Issue(
                uuid=TEST_UUID,
                title="Outdated Dependency",
                description=(
                    "The IPFS node has been compiled with an old dependency version. "
                    "Consider upgrading it for the latest feature and security updates."
                ),
                severity=Severity.LOW,
                raw_data=(
                    '{"Path": "<string>", "Sum": "<string>", '
                    '"ReplacedBy": "<string>", "Version": "<string>"}'
                ),
            ),
        ],
        id="DependencyVersion dep-check success issues logged",
    ),
    pytest.param(
        DependencyVersion(),
        NodeType.IPFS,
        (
            {
                "json": {
                    "Path": "<string>",
                    "Sum": "<string>",
                    "ReplacedBy": "",
                    "Version": "<string>",
                }
            },
        ),
        "/api/v0/version/deps",
        [
            Issue(
                uuid=TEST_UUID,
                title="Dependency Version Information Leak",
                description=(
                    "Dependency version information is exposed. "
                    "This allows an attacker to obtain information about the system's Go version, "
                    "operating system, as well as the IPFS node's version and origin repository"
                ),
                severity=Severity.LOW,
                raw_data=(
                    '[{"Path": "<string>", "Sum": "<string>", "ReplacedBy": "", '
                    '"Version": "<string>"}]'
                ),
            )
        ],
        id="DependencyVersion dep-check success no issue logged",
    ),
    pytest.param(
        DependencyVersion(check_dependencies=False),
        NodeType.IPFS,
        (
            {
                "json": {
                    "Path": "<string>",
                    "Sum": "<string>",
                    "ReplacedBy": "",
                    "Version": "<string>",
                }
            },
        ),
        "/api/v0/version/deps",
        [
            Issue(
                uuid=TEST_UUID,
                title="Dependency Version Information Leak",
                description=(
                    "Dependency version information is exposed. "
                    "This allows an attacker to obtain information about the system's Go version, "
                    "operating system, as well as the IPFS node's version and origin repository"
                ),
                severity=Severity.LOW,
                raw_data=(
                    '[{"Path": "<string>", "Sum": "<string>", "ReplacedBy": "", '
                    '"Version": "<string>"}]'
                ),
            ),
        ],
        id="DependencyVersion no dep-check success issue logged",
    ),
    pytest.param(
        DependencyVersion(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/version/deps",
        [],
        id="DependencyVersion failed no issue logged",
    ),
    pytest.param(
        DependencyVersion(),
        NodeType.GETH,
        [],
        "/api/v0/version/deps",
        [],
        id="DependencyVersion bad node no issue logged",
    ),
]


# P2PListListeners
TESTCASES += [
    pytest.param(
        P2PListListeners(),
        NodeType.IPFS,
        (
            {
                "json": {
                    "Listeners": [
                        {
                            "ListenAddress": "<string>",
                            "Protocol": "<string>",
                            "TargetAddress": "<string>",
                        }
                    ]
                }
            },
        ),
        "/api/v0/p2p/ls",
        [
            Issue(
                uuid=TEST_UUID,
                title="Exposed P2P Listener List",
                description=(
                    "Anyone is able to list the P2P listener services running on this node. "
                    "This method may leak internal information on other peer-to-peer services "
                    "running on this node."
                ),
                severity=Severity.LOW,
                raw_data=(
                    '{"Listeners": [{"ListenAddress": "<string>", '
                    '"Protocol": "<string>", "TargetAddress": "<string>"}]}'
                ),
            )
        ],
        id="P2PListListeners success issue logged",
    ),
    pytest.param(
        P2PListListeners(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/p2p/ls",
        [],
        id="P2PListListeners failed no issue logged",
    ),
    pytest.param(
        P2PListListeners(),
        NodeType.GETH,
        [],
        "/api/v0/p2p/ls",
        [],
        id="P2PListListeners bad node no issue logged",
    ),
]


# P2PListStreams
TESTCASES += [
    pytest.param(
        P2PListStreams(),
        NodeType.IPFS,
        (
            {
                "json": {
                    "Streams": [
                        {
                            "HandlerID": "<string>",
                            "OriginAddress": "<string>",
                            "Protocol": "<string>",
                            "TargetAddress": "<string>",
                        }
                    ]
                }
            },
        ),
        "/api/v0/p2p/stream/ls",
        [
            Issue(
                uuid=TEST_UUID,
                title="Exposed P2P Stream List",
                description=(
                    "Anyone is able to list the active P2P streams on this node. "
                    "This method may leak internal information on other peer-to-peer services "
                    "and connections on this node."
                ),
                severity=Severity.LOW,
                raw_data=(
                    '{"Streams": [{"HandlerID": "<string>", "OriginAddress": "<string>", '
                    '"Protocol": "<string>", "TargetAddress": "<string>"}]}'
                ),
            )
        ],
        id="P2PListStreams success issue logged",
    ),
    pytest.param(
        P2PListStreams(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/p2p/stream/ls",
        [],
        id="P2PListStreams failed no issue logged",
    ),
    pytest.param(
        P2PListStreams(),
        NodeType.GETH,
        [],
        "/api/v0/p2p/stream/ls",
        [],
        id="P2PListStreams bad node no issue logged",
    ),
]


# P2PCloseStream
TESTCASES += [
    pytest.param(
        P2PCloseStream(),
        NodeType.IPFS,
        ({"text": ""},),
        "/api/v0/p2p/stream/close",
        [
            Issue(
                uuid=TEST_UUID,
                title="Exposed P2P Stream Management endpoint",
                description=(
                    "Anyone is able to close active P2P streams on this node. "
                    "This exposed functionality may be used by an attacker to "
                    "disrupt the node's availability and block connections."
                ),
                severity=Severity.HIGH,
                raw_data="",
            )
        ],
        id="P2PCloseStream success issue logged",
    ),
    pytest.param(
        P2PCloseStream(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/p2p/stream/close",
        [],
        id="P2PCloseStream failed no issue logged",
    ),
    pytest.param(
        P2PCloseStream(),
        NodeType.GETH,
        [],
        "/api/v0/p2p/stream/close",
        [],
        id="P2PCloseStream bad node no issue logged",
    ),
]


# P2PStopForwarding
TESTCASES += [
    pytest.param(
        P2PStopForwarding(),
        NodeType.IPFS,
        ({"text": "1"},),
        "/api/v0/p2p/close",
        [
            Issue(
                uuid=TEST_UUID,
                title="Exposed P2P Management endpoint",
                description=(
                    "Anyone is able to close active P2P forwardings on this node. "
                    "This exposed functionality may be used by an attacker to "
                    "disrupt the node's availability and block connections."
                ),
                severity=Severity.HIGH,
                raw_data="1",
            )
        ],
        id="P2PStopForwarding success issue logged",
    ),
    pytest.param(
        P2PStopForwarding(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/p2p/close",
        [],
        id="P2PStopForwarding failed no issue logged",
    ),
    pytest.param(
        P2PStopForwarding(),
        NodeType.GETH,
        [],
        "/api/v0/p2p/close",
        [],
        id="P2PStopForwarding bad node no issue logged",
    ),
]


# P2PEnableForwarding
TESTCASES += [
    pytest.param(
        P2PEnableForwarding(),
        NodeType.IPFS,
        ({"text": ""},),
        "/api/v0/p2p/forward",
        [
            Issue(
                uuid=TEST_UUID,
                title="Exposed P2P Management endpoint",
                description=(
                    "Anyone is able to register P2P forwardings on this node. "
                    "This exposed functionality may be used by an attacker to "
                    "disrupt the node's availability and block connections."
                ),
                severity=Severity.HIGH,
                raw_data="",
            )
        ],
        id="P2PEnableForwarding success issue logged",
    ),
    pytest.param(
        P2PEnableForwarding(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/p2p/forward",
        [],
        id="P2PEnableForwarding failed no issue logged",
    ),
    pytest.param(
        P2PEnableForwarding(),
        NodeType.GETH,
        [],
        "/api/v0/p2p/forward",
        [],
        id="P2PEnableForwarding bad node no issue logged",
    ),
]


# P2PCreateListener
TESTCASES += [
    pytest.param(
        P2PCreateListener(),
        NodeType.IPFS,
        ({"text": ""},),
        "/api/v0/p2p/listen",
        [
            Issue(
                uuid=TEST_UUID,
                title="Exposed P2P Management endpoint",
                description=(
                    "Anyone is able to register P2P listeners on this node. "
                    "This exposed functionality may be used by an attacker to "
                    "disrupt the node's availability and block connections."
                ),
                severity=Severity.HIGH,
                raw_data="",
            )
        ],
        id="P2PCreateListener success issue logged",
    ),
    pytest.param(
        P2PCreateListener(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/p2p/listen",
        [],
        id="P2PCreateListener failed no issue logged",
    ),
    pytest.param(
        P2PCreateListener(),
        NodeType.GETH,
        [],
        "/api/v0/p2p/listen",
        [],
        id="P2PCreateListener bad node no issue logged",
    ),
]


# EnumerateLogs
TESTCASES += [
    pytest.param(
        EnumerateLogs(),
        NodeType.IPFS,
        ({"json": {"Strings": ["<string>"]}},),
        "/api/v0/log/ls",
        [
            Issue(
                uuid=TEST_UUID,
                title="Exposed Logging Subsystem Data",
                description=(
                    "It is possible to list the logging subsystems that the node "
                    "is using. This may be used by an attacker to find non-standard "
                    "customizations on the node, as well as fingerprint the node setup "
                    "for identification."
                ),
                severity=Severity.LOW,
                raw_data='{"Strings": ["<string>"]}',
            )
        ],
        id="EnumerateLogs success issue logged",
    ),
    pytest.param(
        EnumerateLogs(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/log/ls",
        [],
        id="EnumerateLogs failed no issue logged",
    ),
    pytest.param(
        EnumerateLogs(),
        NodeType.GETH,
        [],
        "/api/v0/log/ls",
        [],
        id="EnumerateLogs bad node no issue logged",
    ),
]

# ReadLogs
TESTCASES += [
    pytest.param(
        ReadLogs(),
        NodeType.IPFS,
        ({"text": "test log\n"},),
        "/api/v0/log/tail",
        [
            Issue(
                uuid=TEST_UUID,
                title="Exposed System Log Data",
                description=(
                    "Anyone can list log messages generated by the node. Log messages, "
                    "especially debug-level ones, can leak sensitive information about "
                    "the node's setup and operations running on it."
                ),
                severity=Severity.MEDIUM,
                raw_data="test log\n",
            )
        ],
        id="ReadLogs success issue logged",
    ),
    pytest.param(
        ReadLogs(),
        NodeType.IPFS,
        ({"text": "test log\n" * 5},),
        "/api/v0/log/tail",
        [
            Issue(
                uuid=TEST_UUID,
                title="Exposed System Log Data",
                description=(
                    "Anyone can list log messages generated by the node. Log messages, "
                    "especially debug-level ones, can leak sensitive information about "
                    "the node's setup and operations running on it."
                ),
                severity=Severity.MEDIUM,
                raw_data="test log\n" * 2,  # reduced due to steam limit
            )
        ],
        id="ReadLogs success above stream limit issue logged",
    ),
    pytest.param(
        ReadLogs(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/log/tail",
        [],
        id="ReadLogs failed no issue logged",
    ),
    pytest.param(
        ReadLogs(),
        NodeType.GETH,
        [],
        "/api/v0/log/tail",
        [],
        id="ReadLogs bad node no issue logged",
    ),
]

# ChangeLogLevel
TESTCASES += [
    pytest.param(
        ChangeLogLevel(),
        NodeType.IPFS,
        ({"json": {"Message": "<string>"}},),
        "/api/v0/log/level",
        [
            Issue(
                uuid=TEST_UUID,
                title="Exposed System Log Management",
                description=(
                    "Anyone can change the log level of messages generated by the node. "
                    "Log messages, especially debug-level ones, can leak sensitive information "
                    "about the node's setup and operations running on it. An attacker may unlock "
                    "additional information by enabling debug logs. This could also results in "
                    "degraded performance, espeically when logs are stored in local files, or "
                    "in log aggregation systems unable to handle the load."
                ),
                severity=Severity.MEDIUM,
                raw_data='{"Message": "<string>"}',
            )
        ],
        id="ChangeLogLevel success issue logged",
    ),
    pytest.param(
        ChangeLogLevel(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/log/level",
        [],
        id="ChangeLogLevel failed no issue logged",
    ),
    pytest.param(
        ChangeLogLevel(),
        NodeType.GETH,
        [],
        "/api/v0/log/level",
        [],
        id="ChangeLogLevel bad node no issue logged",
    ),
]


# KeyLeaks
TESTCASES += [
    pytest.param(
        KeyLeaks(export=True),
        NodeType.IPFS,
        (
            {"json": {"Keys": [{"Id": "<string>", "Name": "<string>"}]}},
            {"text": "test"},
        ),
        "/api/v0/key/list",
        [
            Issue(
                uuid=TEST_UUID,
                title="Key List Information Leak",
                description=(
                    "Anyone is able to list the keys registered on the node. The name of "
                    "a key can leak information as well and is required for other actions "
                    "such as exporting the key contents."
                ),
                severity=Severity.MEDIUM,
                raw_data='{"Keys": [{"Id": "<string>", "Name": "<string>"}]}',
            ),
            Issue(
                uuid=TEST_UUID,
                title="Unauthorized Key Export",
                description=(
                    "Anyone can export keys from the node. All secrets should be invalidated, "
                    "rotated, and reapplied. The endpoint must be protected against future "
                    "unauthorized use."
                ),
                severity=Severity.CRITICAL,
                raw_data="test",
            ),
        ],
        id="KeyLeaks list success export issues logged",
    ),
    pytest.param(
        KeyLeaks(export=True),
        NodeType.IPFS,
        (
            {
                "json": {"Keys": [{"Id": "<string>", "Name": "<string>"}]},
            },
            {"status_code": 403},
        ),
        "/api/v0/key/list",
        [
            Issue(
                uuid=TEST_UUID,
                title="Key List Information Leak",
                description=(
                    "Anyone is able to list the keys registered on the node. The name of "
                    "a key can leak information as well and is required for other actions "
                    "such as exporting the key contents."
                ),
                severity=Severity.MEDIUM,
                raw_data='{"Keys": [{"Id": "<string>", "Name": "<string>"}]}',
            ),
        ],
        id="KeyLeaks list success export fail no issue logged",
    ),
    pytest.param(
        KeyLeaks(),
        NodeType.IPFS,
        ({"json": {"Keys": [{"Id": "<string>", "Name": "<string>"}]}},),
        "/api/v0/key/list",
        [
            Issue(
                uuid=TEST_UUID,
                title="Key List Information Leak",
                description=(
                    "Anyone is able to list the keys registered on the node. The name of "
                    "a key can leak information as well and is required for other actions "
                    "such as exporting the key contents."
                ),
                severity=Severity.MEDIUM,
                raw_data='{"Keys": [{"Id": "<string>", "Name": "<string>"}]}',
            ),
        ],
        id="KeyLeaks list no export success issue logged",
    ),
    pytest.param(
        KeyLeaks(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/key/list",
        [],
        id="KeyLeaks failed no issue logged",
    ),
    pytest.param(
        KeyLeaks(),
        NodeType.GETH,
        [],
        "/api/v0/key/list",
        [],
        id="KeyLeaks bad node no issue logged",
    ),
]


# CIDFSEnum
TESTCASES += [
    pytest.param(
        CIDFSEnum(cid_paths=["test"]),
        NodeType.IPFS,
        (
            {
                "json": {
                    "Objects": [
                        {
                            "Hash": "<string>",
                            "Links": [
                                {
                                    "Hash": "<string>",
                                    "Name": "<string>",
                                    "Size": "<uint64>",
                                    "Target": "<string>",
                                    "Type": "<int32>",
                                }
                            ],
                        }
                    ]
                }
            },
            {
                "json": {
                    "Arguments": {"<string>": "<string>"},
                    "Objects": {
                        "<string>": {
                            "Hash": "<string>",
                            "Links": [
                                {
                                    "Hash": "<string>",
                                    "Name": "<string>",
                                    "Size": "<uint64>",
                                    "Type": "<string>",
                                }
                            ],
                            "Size": "<uint64>",
                            "Type": "<string>",
                        }
                    },
                }
            },
        ),
        "/api/v0/ls",
        [
            Issue(
                uuid=TEST_UUID,
                title="Found an Exposed IPFS Content ID",
                description=(
                    "A common IPFS file path is leaking directory contents of UNIX filesystem "
                    "objects. Depending on where IPFS has been mounted, this can leak "
                    f"confidential information. Endpoint: /api/v0/ls"
                ),
                severity=Severity.MEDIUM,
                raw_data=(
                    '{"Objects": [{"Hash": "<string>", "Links": [{"Hash": "<string>", '
                    '"Name": "<string>", "Size": "<uint64>", "Target": "<string>", '
                    '"Type": "<int32>"}]}]}'
                ),
            ),
            Issue(
                uuid=TEST_UUID,
                title="Found an Exposed IPFS Content ID",
                description=(
                    "A common IPFS file path is leaking directory contents of UNIX filesystem "
                    "objects. Depending on where IPFS has been mounted, this can leak "
                    f"confidential information. Endpoint: /api/v0/file/ls"
                ),
                severity=Severity.MEDIUM,
                raw_data=(
                    '{"Arguments": {"<string>": "<string>"}, "Objects": {"<string>": '
                    '{"Hash": "<string>", "Links": [{"Hash": "<string>", "Name": "<string>",'
                    ' "Size": "<uint64>", "Type": "<string>"}], "Size": "<uint64>", "Type": '
                    '"<string>"}}}'
                ),
            ),
        ],
        id="CIDFSEnum success issue logged",
    ),
    pytest.param(
        CIDFSEnum(cid_paths=["test"]),
        NodeType.IPFS,
        ({"status_code": 403}, {"status_code": 403}),
        "/api/v0/ls",
        [],
        id="CIDFSEnum failed no issue logged",
    ),
    pytest.param(
        CIDFSEnum(cid_paths=["test"]),
        NodeType.GETH,
        [],
        "/api/v0/ls",
        [],
        id="CIDFSEnum bad node no issue logged",
    ),
]


# UnixFSEnum
TESTCASES += [
    pytest.param(
        UnixFSEnum(),
        NodeType.IPFS,
        (
            {
                "json": {
                    "Entries": [
                        {
                            "Hash": "<string>",
                            "Name": "<string>",
                            "Size": "<int64>",
                            "Type": "<int>",
                        }
                    ]
                }
            },
        ),
        "/api/v0/files/ls",
        [
            Issue(
                uuid=TEST_UUID,
                title="Found an Exposed UNIX Filesystem Root",
                description=(
                    "The UNIX root directory path is leaking contents of UNIX filesystem "
                    "objects. An attacker can use this endpoint along with the /files/read "
                    "endpoint to enumerate potentially confidential data on the system."
                ),
                severity=Severity.MEDIUM,
                raw_data=(
                    '{"Entries": [{"Hash": "<string>", "Name": "<string>", '
                    '"Size": "<int64>", "Type": "<int>"}]}'
                ),
            ),
        ],
        id="UnixFSEnum success issue logged",
    ),
    pytest.param(
        UnixFSEnum(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/files/ls",
        [],
        id="UnixFSEnum failed no issue logged",
    ),
    pytest.param(
        UnixFSEnum(),
        NodeType.GETH,
        [],
        "/api/v0/files/ls",
        [],
        id="UnixFSEnum bad node no issue logged",
    ),
]


# UnixFSEnum
TESTCASES += [
    pytest.param(
        FilestoreEnum(),
        NodeType.IPFS,
        (
            {
                "json": {
                    "ErrorMsg": "<string>",
                    "FilePath": "<string>",
                    "Key": {"/": "<cid-string>"},
                    "Offset": "<uint64>",
                    "Size": "<uint64>",
                    "Status": "<int32>",
                }
            },
        ),
        "/api/v0/filestore/ls",
        [
            Issue(
                uuid=TEST_UUID,
                title="Found Exposed Filestore Objects",
                description=(
                    "The filestore endpoint is leaking contents of its objects. An attacker "
                    "can use this endpoint to enumerate potentially confidential data on the "
                    "system."
                ),
                severity=Severity.MEDIUM,
                raw_data=(
                    '{"ErrorMsg": "<string>", "FilePath": "<string>", "Key": '
                    '{"/": "<cid-string>"}, "Offset": "<uint64>", "Size": "<uint64>", '
                    '"Status": "<int32>"}'
                ),
            ),
        ],
        id="FilestoreEnum success issue logged",
    ),
    pytest.param(
        FilestoreEnum(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/filestore/ls",
        [],
        id="FilestoreEnum failed no issue logged",
    ),
    pytest.param(
        FilestoreEnum(),
        NodeType.GETH,
        [],
        "/api/v0/filestore/ls",
        [],
        id="FilestoreEnum bad node no issue logged",
    ),
]


# CommandCheck
TESTCASES += [
    pytest.param(
        CommandCheck(denylist=[("tar",)]),
        NodeType.IPFS,
        (
            {
                "json": {
                    "Name": "<string>",
                    "Options": [{"Names": ["<string>"]}],
                    "Subcommands": [
                        {
                            "Name": "tar",
                            "Options": [{"Names": ["<string>"]}],
                            "Subcommands": [{"Name": "add"}],
                        }
                    ],
                }
            },
        ),
        "/api/v0/commands",
        [
            Issue(
                uuid=TEST_UUID,
                title="Forbidden Method is Exposed",
                description=(
                    "A forbidden API method is open to the Internet. Attackers "
                    "may be able to use the exposed functionality to cause undesired "
                    "effects to the system."
                ),
                severity=Severity.HIGH,
                raw_data=(
                    '{"Name": "tar", "Options": [{"Names": ["<string>"]}], "Subcommands": '
                    '[{"Name": "add"}]}'
                ),
            ),
            Issue(
                uuid=TEST_UUID,
                title="Forbidden Method is Exposed",
                description=(
                    "A forbidden API method is open to the Internet. Attackers "
                    "may be able to use the exposed functionality to cause undesired "
                    "effects to the system."
                ),
                severity=Severity.HIGH,
                raw_data='{"Name": "add"}',
            ),
        ],
        id="CommandCheck success denylist issue logged",
    ),
    pytest.param(
        CommandCheck(denylist=[("tar",)]),
        NodeType.IPFS,
        ({"json": {}},),
        "/api/v0/commands",
        [],
        id="CommandCheck success empty result no issue logged",
    ),
    pytest.param(
        CommandCheck(allowlist=[("tar", "add")]),
        NodeType.IPFS,
        (
            {
                "json": {
                    "Name": "<string>",
                    "Options": [{"Names": ["<string>"]}],
                    "Subcommands": [
                        {
                            "Name": "tar",
                            "Options": [{"Names": ["<string>"]}],
                            "Subcommands": [{"Name": "add"}],
                        }
                    ],
                }
            },
        ),
        "/api/v0/commands",
        [
            Issue(
                uuid=TEST_UUID,
                title="Forbidden Method is Exposed",
                description=(
                    "A forbidden API method is open to the Internet. Attackers "
                    "may be able to use the exposed functionality to cause undesired "
                    "effects to the system."
                ),
                severity=Severity.HIGH,
                raw_data=(
                    '{"Name": "tar", "Options": [{"Names": ["<string>"]}], "Subcommands": '
                    '[{"Name": "add"}]}'
                ),
            ),
        ],
        id="CommandCheck success allowlist no issue logged",
    ),
    pytest.param(
        CommandCheck(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/commands",
        [],
        id="CommandCheck failed no issue logged",
    ),
    pytest.param(
        CommandCheck(),
        NodeType.GETH,
        [],
        "/api/v0/commands",
        [],
        id="CommandCheck bad node no issue logged",
    ),
]


# OpenUploadAdd
TESTCASES += [
    pytest.param(
        OpenUploadAdd(),
        NodeType.IPFS,
        (
            {
                "json": {
                    "Bytes": "<int64>",
                    "Hash": "<string>",
                    "Name": "<string>",
                    "Size": "<string>",
                }
            },
        ),
        "/api/v0/add",
        [
            Issue(
                uuid=TEST_UUID,
                title="Anyone can upload data to the node",
                description=(
                    "Anyone is able to upload files to the node. An attacker can use this to "
                    "upload large amounts of data and thus prevent the node from accepting "
                    "further uploads, performing a Denial of Service (DoS) attack."
                ),
                severity=Severity.HIGH,
                raw_data=(
                    '{"Bytes": "<int64>", "Hash": "<string>", '
                    '"Name": "<string>", "Size": "<string>"}'
                ),
            ),
        ],
        id="OpenUploadAdd success issue logged",
    ),
    pytest.param(
        OpenUploadAdd(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/add",
        [],
        id="OpenUploadAdd failed no issue logged",
    ),
    pytest.param(
        OpenUploadAdd(),
        NodeType.GETH,
        [],
        "/api/v0/add",
        [],
        id="OpenUploadAdd bad node no issue logged",
    ),
]


# OpenUploadTarAdd
TESTCASES += [
    pytest.param(
        OpenUploadTarAdd(),
        NodeType.IPFS,
        (
            {
                "json": {
                    "Bytes": "<int64>",
                    "Hash": "<string>",
                    "Name": "<string>",
                    "Size": "<string>",
                }
            },
        ),
        "/api/v0/add",
        [
            Issue(
                uuid=TEST_UUID,
                title="Anyone can upload compressed data to the node",
                description=(
                    "Anyone is able to upload files to the node. An attacker can use this to "
                    "upload large amounts of data and thus prevent the node from accepting "
                    "further uploads, performing a Denial of Service (DoS) attack."
                ),
                severity=Severity.HIGH,
                raw_data=(
                    '{"Bytes": "<int64>", "Hash": "<string>", '
                    '"Name": "<string>", "Size": "<string>"}'
                ),
            ),
        ],
        id="OpenUploadTarAdd success issue logged",
    ),
    pytest.param(
        OpenUploadTarAdd(),
        NodeType.IPFS,
        ({"status_code": 403},),
        "/api/v0/add",
        [],
        id="OpenUploadTarAdd failed no issue logged",
    ),
    pytest.param(
        OpenUploadTarAdd(),
        NodeType.GETH,
        [],
        "/api/v0/add",
        [],
        id="OpenUploadTarAdd bad node no issue logged",
    ),
]


@pytest.mark.parametrize(
    "plugin,node_type,rpc_results,endpoint,issues",
    TESTCASES,
)
@patch(
    target="teatime.reporting.issue.uuid4",
    new=Mock(return_value=uuid.UUID(TEST_UUID)),
)
def test_issues(plugin, node_type, rpc_results, endpoint, issues):
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
        # TODO: allow for endpoint list if multiple are hit
        mock.request_history[i].url.endswith(endpoint)

    assert context.report.meta == {plugin.__class__.__name__: True}
    assert len(context.report.issues) == len(issues)
    for i1, i2 in zip(context.report.issues, issues):
        # compare dict representations here for more verbose failure diffs
        assert i1.to_dict() == i2.to_dict()


def test_command_overlap():
    with pytest.raises(PluginException):
        CommandCheck(allowlist=[("tar", "add")], denylist=[("tar", "add")])
