"""Small SFTP v3 test client over the system ssh binary; no extra dependencies."""

import os
import select
import struct
import subprocess
import time


def u32(value):
    return struct.pack(">I", value)


def string(value):
    if isinstance(value, str):
        value = value.encode()
    return u32(len(value)) + value


class SFTPError(Exception):
    pass


class SFTP:
    def __init__(self, port, key, known_hosts, user="alice", extra=()):
        self.args = [
            "ssh",
            "-p",
            str(port),
            "-i",
            str(key),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=3",
            "-o",
            "UserKnownHostsFile=" + str(known_hosts),
            *extra,
        ]
        self.process = subprocess.Popen(
            self.args + ["-s", user + "@127.0.0.1", "sftp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.sequence = 0
        try:
            self.send(1, u32(3))
            kind, data = self.receive()
            if kind != 2 or data[:4] != u32(3):
                raise SFTPError("SFTP version negotiation failed")
        except Exception:
            self.close()
            raise

    def send(self, kind, data):
        self.process.stdin.write(u32(len(data) + 1) + bytes([kind]) + data)
        self.process.stdin.flush()

    def read(self, count):
        data = b""
        deadline = time.monotonic() + 8
        while len(data) < count:
            if not select.select([self.process.stdout], [], [], max(0, deadline - time.monotonic()))[0]:
                raise SFTPError("SFTP response timed out")
            chunk = os.read(self.process.stdout.fileno(), count - len(data))
            if not chunk:
                raise SFTPError("SSH/SFTP connection closed")
            data += chunk
        return data

    def receive(self):
        size = struct.unpack(">I", self.read(4))[0]
        if not 1 <= size <= 1024 * 1024:
            raise SFTPError("Invalid SFTP packet")
        data = self.read(size)
        return data[0], data[1:]

    def request(self, kind, payload):
        self.sequence += 1
        self.send(kind, u32(self.sequence) + payload)
        kind, response = self.receive()
        if response[:4] != u32(self.sequence):
            raise SFTPError("Mismatched SFTP request")
        response = response[4:]
        if kind == 101:
            code = struct.unpack(">I", response[:4])[0]
            if code:
                raise SFTPError("SFTP status " + str(code))
        return kind, response

    def open(self, path, flags=2 | 8 | 16):
        kind, response = self.request(3, string(path) + u32(flags) + u32(0))
        if kind != 102:
            raise SFTPError("Expected an SFTP handle")
        size = struct.unpack(">I", response[:4])[0]
        return response[4 : 4 + size]

    def write(self, handle, content, offset=0):
        for start in range(0, len(content), 32768):
            self.request(6, string(handle) + struct.pack(">Q", offset + start) + string(content[start : start + 32768]))

    def close_handle(self, handle):
        self.request(4, string(handle))

    def put(self, path, content):
        handle = self.open(path)
        self.write(handle, content)
        self.close_handle(handle)

    def close(self):
        process = getattr(self, "process", None)
        if process is None:
            return
        if process.stdin and not process.stdin.closed:
            try:
                process.stdin.close()
            except BrokenPipeError:
                pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stdout.close()
        process.stderr.close()
