"""Bounded, one-request Unix-socket protocol; never accepts filesystem paths."""

import json
import socket
import struct

SOCKET = "/reader/archive.sock"
MAX_FRAME = 128 * 1024
CHUNK = 64 * 1024


class ArchiveError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message
        super().__init__(message)


def exact(connection, size):
    data = bytearray()
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part:
            raise OSError("Incomplete archive response")
        data.extend(part)
    return bytes(data)


def receive(connection, limit=MAX_FRAME):
    size = struct.unpack("!I", exact(connection, 4))[0]
    if not 1 <= size <= limit:
        raise ValueError("Invalid archive frame")
    from common import decode_json

    value = decode_json(exact(connection, size))
    if not isinstance(value, dict):
        raise ValueError("Invalid archive message")
    return value


def send(connection, value):
    data = json.dumps(value, separators=(",", ":")).encode()
    if len(data) > MAX_FRAME:
        raise ValueError("Archive response exceeds limit")
    connection.sendall(struct.pack("!I", len(data)) + data)


class Download:
    def __init__(self, connection, metadata):
        self.connection, self.metadata = connection, metadata

    def __iter__(self):
        remaining = self.metadata["size"]
        try:
            while remaining:
                block = self.connection.recv(min(CHUNK, remaining))
                if not block:
                    raise OSError("Archive download interrupted")
                remaining -= len(block)
                yield block
        finally:
            self.close()

    def close(self):
        self.connection.close()


class Client:
    def __init__(self, path=SOCKET):
        self.path = str(path)

    def request(self, operation, **params):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(60)
        try:
            connection.connect(self.path)
            send(connection, dict(operation=operation, **params))
            value = receive(connection)
            if value.get("status") != 200:
                raise ArchiveError(value.get("status", 503), value.get("error", "Archive unavailable"))
            if operation == "download":
                return Download(connection, value["data"])
            connection.close()
            return value["data"]
        except Exception:
            connection.close()
            raise
