"""The main test script."""

import json
import subprocess
import sys

from teatime.plugins import NodeType
from teatime.plugins.eth1 import (
    GethStartWebsocket,
    GethStopWebsocket,
    NodeVersion,
    ParityUpgrade,
    TxPoolContent,
    ParityTxPoolStatistics,
    GethTxPoolStatus,
    GethTxPoolInspection,
    ParityTxFloor,
    ParityTxCeiling,
    NodeSyncedCheck,
    SHA3Check,
    GethStopRPC,
    GethStartRPC,
    AccountUnlock,
    OpenAccounts,
    PeerlistManipulation,
    PeerCountStatus,
    ParityDropPeers,
    NetworkListening,
    MiningStatus,
    HashrateStatus,
    ParityChangeCoinbase,
    ParitySyncMode,
    ParityChangeTarget,
    ParityChangeExtra,
    PeerlistLeak,
    ParityDevLogs,
    GethNodeInfo,
    GethDatadir,
    ParityGasFloor,
    ParityGasCeiling,
    AccountImport,
    AccountCreation,
)
from teatime.scanner.scanner import Scanner

# ETH1 random stuck node
# IP = "13.94.241.95"
# PORT = 8545

# ETH1 Impact Hub
# IP = "192.168.40.52"
# PORT = 8545

# ETH1 Shodan rando
IP = "178.128.193.195"
PORT = 8545


def check_connectivity(target):
    """Check target connectivity by pinging it."""

    command = ["ping", "-c", "1", target]
    retval = subprocess.call(
        command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return retval == 0


scanner = Scanner(
    target=f"http://{IP}:{PORT}",
    node_type=NodeType.GETH,
    plugins=[AccountUnlock(wordlist=["test"])],
)

if not check_connectivity(IP):
    print("Node is not reachable")
    sys.exit(1)

print(json.dumps(scanner.run().to_dict(), indent=2, sort_keys=True))
