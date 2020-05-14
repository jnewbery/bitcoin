# Example node-shell usage:

```
REPO_PATH="<path_to_repo>"
DATADIR_PATH="<path_to_datadir>"
import sys
sys.path.insert(0, f"{REPO_PATH}/test/functional")
from test_framework.node_shell import NodeShell
test = NodeShell()
test.setup(datadir=DATADIR_PATH)
# <test_framework.node_shell.NodeShell.__TestShell object at 0x7f7704820490>
node = test.nodes[0]
bb = node.getbestblockhash()
# {'version': 199900, 'subversion': '/Satoshi:0.19.99/', ...
from test_framework.messages import FILTER_TYPE_BASIC, msg_getcfcheckpt
request = msg_getcfcheckpt(filter_type=FILTER_TYPE_BASIC, stop_hash=int(bb, 16))
for i in range(25):
    with node.debug_log_delta("getcfcheckpt request received", "cfcheckpt response constructed"):
        node.p2ps[0].send_and_ping(request)
test.shutdown()
```
