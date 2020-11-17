import json

from teatime import Context, NodeType, Scanner
from teatime.plugins.ipfs.commands import CommandCheck

s = Scanner(
    ip="136.144.57.15",
    port=80,
    node_type=NodeType.IPFS,
    plugins=[CommandCheck(allowlist=[("tar", "add")])],
)
report = s.run()

print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
