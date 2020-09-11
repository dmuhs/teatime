from teatime.scanner import Scanner
from teatime.plugins.context import NodeType
from teatime.plugins.eth1 import GethDatadir, GethNodeInfo, NodeVersion, OpenAccounts, PeerlistLeak


TARGET_IP = "127.0.0.1"
TARGET_PORT = 8545
INFURA_URL = "Infura API Endpoint"
GETH_REPO = "https://api.github.com/repos/ethereum/go-ethereum/releases/latest"


def get_scanner():
    return Scanner(
        ip=TARGET_IP,
        port=TARGET_PORT,
        node_type=NodeType.GETH,
        plugins=[
            GethDatadir(),
            NodeVersion(geth_url=GETH_REPO),
            GethNodeInfo(),
            OpenAccounts(INFURA_URL),
            PeerlistLeak(),
        ]
    )


if __name__ == '__main__':
    scanner = get_scanner()
    report = scanner.run()
    print(report.to_dict())
