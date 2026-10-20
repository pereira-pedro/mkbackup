"""Small WSGI surface. No registry or backup payload access."""

import json
import os
from pathlib import Path

from common import FILENAME
from control_rpc import PUBLIC_SOCKET, Client, ControlError

store = None


def application(environ, start_response):
    global store
    headers = [
        ("Cache-Control", "no-store, private"),
        ("Pragma", "no-cache"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
    ]

    def respond(status, body, kind="text/plain; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode()
        start_response(status, headers + [("Content-Type", kind), ("Content-Length", str(len(body)))])
        return [body]

    if environ.get("REQUEST_METHOD") != "GET":
        return respond("405 Method Not Allowed", "GET required\n")
    path = environ.get("PATH_INFO", "")
    auth = environ.get("HTTP_AUTHORIZATION", "")
    if len(auth) > 128 or environ.get("QUERY_STRING"):
        return respond("400 Bad Request", "Invalid request\n")
    try:
        if store is None:
            store = Client(PUBLIC_SOCKET)
        # Health checks also remove expired encrypted installers during idle periods.
        if path == "/healthz":
            store.listing()
            return respond("200 OK", "ok\n")
        if path == "/" and not auth:
            return respond(
                "200 OK",
                "mkbackup deployment\nAsk your administrator for a per-router enrollment token.\n"
                "Download with HTTPS certificate validation, then /import file-name=mkbackup-install.rsc.\n",
            )
        if not auth.startswith("Bearer "):
            return respond("401 Unauthorized", "Credential required\n")
        token = auth[7:]
        if path in ("/", "/routeros6.rsc", "/routeros7.rsc"):
            major = None if path == "/" else int(path[9])
            installer = store.redeem(token, major)
            headers.append(("Content-Disposition", 'attachment; filename="mkbackup-install.rsc"'))
            return respond("200 OK", installer, "application/octet-stream")
        if path.startswith("/v1/receipts/"):
            name = path[len("/v1/receipts/") :]
            if not FILENAME.fullmatch(name):
                return respond("400 Bad Request", "Invalid filename\n")
            router = store.authorized_router(token)
            index = Path(os.environ.get("RECEIPT_INDEX", "/receipts")) / (router + ".json")
            try:
                data = json.loads(index.read_bytes())
            except FileNotFoundError:
                return respond("202 Accepted", "PENDING\n")
            if data.get("router") != router or data.get("version") != 1:
                raise RuntimeError("Invalid receipt index")
            receipt = data["receipts"].get(name)
            if receipt is None:
                return respond("202 Accepted", "PENDING\n")
            return respond("200 OK", f"ARCHIVED {name} {receipt['size']}\n")
        return respond("404 Not Found", "Not found\n")
    except ControlError as error:
        if error.status == 503:
            return respond("503 Service Unavailable", "Provisioning unavailable\n")
        return respond("401 Unauthorized", "Credential unavailable; request a new enrollment if download failed\n")
    except ValueError:
        return respond("401 Unauthorized", "Credential unavailable; request a new enrollment if download failed\n")
    except Exception:
        # No exception details: a request may contain enrollment or router secrets.
        return respond("503 Service Unavailable", "Service unavailable\n")
