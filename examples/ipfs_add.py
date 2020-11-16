from teatime import Scanner, NodeType, Context
from teatime.plugins.ipfs.add import OpenUploadTarAdd
import json

s = Scanner(ip="127.0.0.1", port=5001, node_type=NodeType.IPFS, plugins=[OpenUploadTarAdd()])
report = s.run()

print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
