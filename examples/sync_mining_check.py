from teatime.scanner import Scanner
from teatime.plugins.context import NodeType
from teatime.plugins.eth1 import NodeSync, MiningStatus


TARGET_IP = "127.0.0.1"
TARGET_PORT = 8545
INFURA_URL = "Infura API Endpoint"


def get_scanner():
    return Scanner(
        ip=TARGET_IP,
        port=TARGET_PORT,
        node_type=NodeType.GETH,
        plugins=[
            NodeSync(infura_url=INFURA_URL, block_threshold=10),
            MiningStatus(should_mine=False)
        ]
    )


if __name__ == '__main__':
    scanner = get_scanner()
    report = scanner.run()
    print(report.to_dict())
