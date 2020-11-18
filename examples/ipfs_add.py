import json

from teatime import Context, NodeType, Scanner
from teatime.plugins.ipfs.pins import RemovePin

s = Scanner(
    ip="127.0.0.1",
    port=5001,
    node_type=NodeType.IPFS,
    plugins=[RemovePin()],
)
report = s.run()

print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
