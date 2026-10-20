"""Trusted CLI pipe; never passes enrollment credentials in process arguments."""

import json
import sys

from control_rpc import CLI_SOCKET, Client

request = json.loads(sys.stdin.buffer.read(65537))
operation = request.pop("operation")
try:
    print(json.dumps(Client(CLI_SOCKET).request(operation, **request)))
except Exception:
    sys.exit("Provisioning operation failed; use the admin status page or check service health")
