import uuid
from unittest.mock import Mock, patch

import pytest
import requests_mock

from teatime import Context, Issue, NodeType, Report, Severity
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
        ({"text": "test log"},),
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
        mock.request_history[i].url.endswith(endpoint)

    assert context.report.meta == {plugin.__class__.__name__: True}
    assert len(context.report.issues) == len(issues)
    for i1, i2 in zip(context.report.issues, issues):
        # compare dict representations here for more verbose failure diffs
        assert i1.to_dict() == i2.to_dict()
