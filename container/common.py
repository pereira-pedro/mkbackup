"""Shared, strict configuration and filesystem primitives (stdlib only)."""

import base64
import hashlib
import json
import os
import re
import stat
import struct
import tempfile
from pathlib import Path

NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")
FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
DEFAULT_MAX_BYTES = 100 * 1024 * 1024
DONE = ".done.json"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def decode_json(content):
    return json.loads(content, object_pairs_hook=unique_object)


def public_key(line):
    if not isinstance(line, str):
        raise ValueError("Expected an RSA public key string")
    fields = line.strip().split()
    if len(fields) < 2 or fields[0] != "ssh-rsa" or len(line) > 16384:
        raise ValueError("Expected an RSA public key without authorized_keys options")
    raw = base64.b64decode(fields[1], validate=True)
    offset = 0
    parts = []
    for _ in range(3):
        if len(raw) < offset + 4:
            raise ValueError("Invalid SSH key")
        size = struct.unpack_from(">I", raw, offset)[0]
        offset += 4
        if size > 16384 or offset + size > len(raw):
            raise ValueError("Invalid SSH key")
        parts.append(raw[offset : offset + size])
        offset += size
    exponent = int.from_bytes(parts[1], "big")
    modulus = int.from_bytes(parts[2], "big")
    if (
        offset != len(raw)
        or parts[0] != b"ssh-rsa"
        or not parts[1]
        or not parts[2]
        or parts[1][0] & 128
        or parts[2][0] & 128
        or exponent < 3
        or exponent % 2 == 0
        or not 3072 <= modulus.bit_length() <= 8192
        or modulus % 2 == 0
    ):
        raise ValueError("RSA keys must be 3072-8192 bits")
    return "ssh-rsa " + fields[1]


def fingerprint(key):
    raw = base64.b64decode(public_key(key).split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def parse_routers(content):
    config = decode_json(content)
    if (
        not isinstance(config, dict)
        or set(config) != {"version", "routers"}
        or type(config["version"]) is not int
        or config["version"] not in (1, 2)
    ):
        raise ValueError("Expected router registry version 1 or 2")
    if not isinstance(config["routers"], list) or len(config["routers"]) > 1000:
        raise ValueError("Expected at most 1000 routers")
    names, identities, keys = set(), set(), set()
    result = []
    for entry in config["routers"]:
        if not isinstance(entry, dict) or set(entry) - {
            "name",
            "uid",
            "keys",
            "enabled",
            "max_bytes",
            "expected_interval_seconds",
            "transport",
        }:
            raise ValueError("Invalid router entry")
        name, uid = entry.get("name"), entry.get("uid")
        if (
            not isinstance(name, str)
            or not NAME.fullmatch(name)
            or name in {"root", "nobody", "sshd", "ftp"}
            or name in names
        ):
            raise ValueError("Invalid or duplicate router name")
        if type(uid) is not int or not 10000 <= uid <= 60000 or uid in identities:
            raise ValueError("Router UID/GID must be unique and between 10000 and 60000")
        enabled = entry.get("enabled", True)
        if type(enabled) is not bool or not isinstance(entry.get("keys"), list) or len(entry["keys"]) > 16:
            raise ValueError("Invalid router keys/enabled flag")
        transport = entry.get("transport", "sftp")
        if transport not in ("sftp", "ftp") or (transport == "ftp" and entry["keys"]):
            raise ValueError("Expected an explicit FTP or SFTP authentication profile")
        normalized = [public_key(key) for key in entry["keys"]]
        if enabled and transport == "sftp" and not normalized:
            raise ValueError("An enabled router needs at least one key")
        for key in normalized:
            if key in keys:
                raise ValueError("A key must belong to exactly one router and appear only once")
            keys.add(key)
        maximum = entry.get("max_bytes", DEFAULT_MAX_BYTES)
        interval = entry.get("expected_interval_seconds", 86400)
        if (
            type(maximum) is not int
            or not 1 <= maximum <= 1024**4
            or type(interval) is not int
            or not 60 <= interval <= 31536000
        ):
            raise ValueError("Invalid maximum payload size or expected backup interval")
        result.append(
            dict(
                name=name,
                uid=uid,
                keys=normalized,
                enabled=enabled,
                transport=transport,
                max_bytes=maximum,
                expected_interval_seconds=interval,
            )
        )
        names.add(name)
        identities.add(uid)
    return result


def load_routers(path="/run/secrets/routers"):
    if str(path) == "/run/secrets/routers" and os.environ.get("ROUTERS_SNAPSHOT"):
        return load_snapshot()[1]
    with open(path, "rb") as source:
        content = source.read(4 * 1024 * 1024 + 1)
    if len(content) > 4 * 1024 * 1024:
        raise ValueError("Router registry is too large")
    return parse_routers(content)


def load_ftp_passwords(path="/run/secrets/ftp_passwords"):
    if str(path) == "/run/secrets/ftp_passwords" and os.environ.get("FTP_AUTH_SNAPSHOT"):
        value = decode_json(Path(os.environ["FTP_AUTH_SNAPSHOT"]).read_bytes())
        if value.get("generation") != load_snapshot()[0]:
            raise ValueError("Configuration generations differ")
        return parse_ftp_passwords(json.dumps(value["passwords"]).encode())
    data = Path(path).read_bytes()
    return parse_ftp_passwords(data)


def parse_ftp_passwords(data):
    if len(data) > 1024 * 1024:
        raise ValueError("FTP password registry is too large")
    value = decode_json(data)
    if not isinstance(value, dict) or any(
        not NAME.fullmatch(name)
        or not isinstance(password, str)
        or not re.fullmatch(r"\$6\$[./A-Za-z0-9]{8,16}\$[./A-Za-z0-9]{86}", password)
        for name, password in value.items()
    ):
        raise ValueError("Invalid FTP password hashes")
    return value


def load_snapshot():
    data = Path(os.environ["ROUTERS_SNAPSHOT"]).read_bytes()
    if len(data) > 4 * 1024 * 1024:
        raise ValueError("Snapshot exceeds limit")
    value = decode_json(data)
    if type(value.get("generation")) is not int or value["generation"] < 1:
        raise ValueError("Invalid configuration generation")
    return value["generation"], parse_routers(json.dumps(value["registry"]))


def atomic_json(path, content, mode=0o600):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as output:
            json.dump(content, output, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        Path(temporary).unlink(missing_ok=True)


def directory(path, mode=0o755, uid=0, gid=0):
    path = Path(path)
    try:
        path.mkdir(mode=mode)
    except FileExistsError:
        pass
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise ValueError("Refusing a non-directory or symlink")
    os.chown(path, uid, gid, follow_symlinks=False)
    path.chmod(mode)
