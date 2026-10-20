import json
import socket
import sys
import time
import urllib.request
from pathlib import Path

if sys.argv[1:] == ["provisioner"]:
    from control_rpc import CLI_SOCKET, Client

    if Client(CLI_SOCKET).request("health") != dict(ready=True):
        raise SystemExit(1)
elif sys.argv[1:] == ["collector"]:
    state = json.loads(Path("/run/mkbackup/collector-status.json").read_text())
    if not state["healthy"] or time.time() - state["heartbeat"] > 300:
        raise SystemExit(1)
elif sys.argv[1:] == ["archive-reader"]:
    from archive_rpc import Client

    if Client().request("health") != dict(ready=True):
        raise SystemExit(1)
elif sys.argv[1:] in (["enrollment"], ["admin"]):
    with urllib.request.urlopen("http://127.0.0.1:8080/healthz", timeout=3) as response:  # nosec B310
        if response.read(16) != b"ok\n":
            raise SystemExit(1)
elif sys.argv[1:] == ["ftp"]:
    with socket.create_connection(("127.0.0.1", 2121), timeout=3) as connection:
        if not connection.recv(256).startswith(b"220"):
            raise SystemExit(1)
else:
    with socket.create_connection(("127.0.0.1", 2222), timeout=3) as connection:
        if not connection.recv(256).startswith(b"SSH-2.0-"):
            raise SystemExit(1)
