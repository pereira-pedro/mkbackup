"""Bounded Unix-socket control protocol with separate public/admin/CLI surfaces."""

import json
import socket
import struct

from common import decode_json

ADMIN_SOCKET = "/control-admin/admin.sock"
PUBLIC_SOCKET = "/control-public/public.sock"
CLI_SOCKET = "/run/mkbackup/cli.sock"
MAX_FRAME = 8 * 1024 * 1024


class ControlError(ValueError):
    def __init__(self, message, status=400):
        self.status = status
        super().__init__(message)


def exact(connection, size):
    data = bytearray()
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part:
            raise OSError("Control connection interrupted")
        data.extend(part)
    return bytes(data)


def receive(connection, limit=MAX_FRAME):
    size = struct.unpack("!I", exact(connection, 4))[0]
    if not 1 <= size <= limit:
        raise ControlError("Invalid control frame")
    value = decode_json(exact(connection, size))
    if not isinstance(value, dict):
        raise ControlError("Invalid control message")
    return value


def send(connection, value):
    payload = json.dumps(value, separators=(",", ":")).encode()
    if len(payload) > MAX_FRAME:
        raise ControlError("Control response exceeds limit")
    connection.sendall(struct.pack("!I", len(payload)) + payload)


class Client:
    def __init__(self, path=ADMIN_SOCKET):
        self.path = str(path)

    def request(self, operation, **parameters):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(15)
            connection.connect(self.path)
            send(connection, dict(operation=operation, **parameters))
            response = receive(connection)
        if response.get("status") != 200:
            raise ControlError(response.get("error", "Provisioning unavailable"), response.get("status", 503))
        return response["data"]

    def listing(self):
        return self.request("health")

    def redeem(self, token, major=None):
        import base64

        return base64.b64decode(self.request("redeem", token=token, major=major)["installer"], validate=True)

    def authorized_router(self, token):
        return self.request("authorize", token=token)["router"]
