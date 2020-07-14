"""The main test script."""

import json
import subprocess
import sys

from teatime.plugins import NodeType
from teatime.scanner import ETH1ScannerConfig, ScannerFactory

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


scanner = ScannerFactory.build_eth1(
    scanner_config=ETH1ScannerConfig(
        uri=f"http://{IP}:{PORT}",
        node_type=NodeType.GETH,
        account_creation={
            "enabled": True,
            "settings": {
                "test_privkey": "c7d26c414625a995584b347db39ebfce03129acb6386d5b2533a698614c138dc",
                "test_password": "fjaal38!dj==42",
            },
        },
        admin_info={
            "enabled": True,
            "settings": {
                "test_enode": (
                    "enode://6f8a80d14311c39f35f516fa664deaaaa13"
                    "e85b2f7493f37f6144d86991ec012937307647bd3b9"
                    "a82abe2974e1407241d54947bbb39763a4cac9f7716"
                    "6ad92a0@10.3.58.6:30303?discport=30301"
                )
            },
        },
        mining={
            "enabled": True,
            "settings": {"should_mine": False, "expected_hashrate": 0},
        },
        network={"enabled": True, "settings": {"minimum_peercount": 15}},
        accounts={
            "enabled": True,
            "settings": {
                "wordlist": [
                    "",  # lol no way
                    "hunter2",  # from parity docs
                    "admin",
                    "password",
                    "test",
                    "ethereum",
                ]
            },
        },
        sha3={
            "enabled": True,
            "settings": {
                "test_input": "0x68656c6c6f20776f726c64",
                "test_output": "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad",
            },
        },
        syncing={
            "enabled": True,
            "settings": {
                "infura_url": "https://mainnet.infura.io/v3/a17bd235fd4147259d03784b24bd3a62"
            },
        },
        txpool={"enabled": True, "settings": {}},
        version={"enabled": True, "settings": {}},
    )
)

if not check_connectivity(IP):
    print("Node is not reachable")
    sys.exit(1)

print(json.dumps(scanner.run().to_dict(), indent=2, sort_keys=True))
