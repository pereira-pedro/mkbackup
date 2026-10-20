"""Receipt-backed 7 recent + 12 calendar-month retention; never traverse legacy data."""

import hashlib
import json
import os
import stat
from datetime import datetime, timezone

from collector import DIR_FLAGS, digest_file, exclusive_json, log, read_small, subdir
from common import FILENAME, atomic_json, decode_json


def inventory(archive_fd, receipts_fd):
    records = []
    names = os.listdir(receipts_fd)
    if len(names) > 10000:
        raise ValueError("Receipt scan limit reached; refusing retention")
    for filename in names:
        if filename.startswith(".tmp-"):
            continue
        if not filename.endswith(".json"):
            raise ValueError("Unexpected receipt entry; refusing retention")
        raw, info = read_small(receipts_fd, filename)
        receipt = decode_json(raw)
        name = receipt.get("filename") if isinstance(receipt, dict) else None
        if (
            info.st_uid != os.geteuid()
            or info.st_mode & 0o222
            or not isinstance(name, str)
            or not FILENAME.fullmatch(name)
            or filename != name + ".json"
            or receipt.get("version") != 1
            or type(receipt.get("size")) is not int
            or receipt["size"] < 1
            or not isinstance(receipt.get("sha256"), str)
            or len(receipt["sha256"]) != 64
            or any(char not in "0123456789abcdef" for char in receipt["sha256"])
        ):
            raise ValueError("Unsafe archive receipt; refusing retention")
        if not isinstance(receipt.get("archived_at"), str):
            raise ValueError("Invalid archive timestamp")
        when = datetime.fromisoformat(receipt["archived_at"])
        if when.tzinfo is None:
            raise ValueError("Receipt timestamp must include timezone")
        receipt["_when"] = when.astimezone(timezone.utc)
        payload = os.stat(name, dir_fd=archive_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(payload.st_mode)
            or payload.st_nlink != 1
            or payload.st_uid != os.geteuid()
            or payload.st_mode & 0o222
            or payload.st_size != receipt["size"]
        ):
            raise ValueError("Unsafe archive inode; refusing retention")
        records.append(receipt)
    return records


def selection(records, now=None):
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    ordered = sorted(records, key=lambda row: (row["_when"], row["filename"]))
    keep = {row["filename"] for row in ordered[-7:]}
    months = {}
    current = now.year * 12 + now.month - 1
    for row in ordered:
        age = current - (row["_when"].year * 12 + row["_when"].month - 1)
        if 0 <= age < 12:
            months.setdefault((row["_when"].year, row["_when"].month), row["filename"])
    keep.update(months.values())
    return keep


def finish_prunes(archive_fd, receipts_fd, router):
    # Durable intent allows recovery after unlink(payload) but before unlink(receipt).
    for filename in os.listdir(archive_fd):
        if not filename.startswith(".prune-") or not filename.endswith(".json"):
            continue
        raw, info = read_small(archive_fd, filename)
        value = decode_json(raw)
        name = value.get("filename") if isinstance(value, dict) else None
        if (
            info.st_uid != os.geteuid()
            or info.st_mode & 0o222
            or not isinstance(name, str)
            or not FILENAME.fullmatch(name)
            or filename != ".prune-" + hashlib.sha256(name.encode()).hexdigest() + ".json"
        ):
            raise ValueError("Invalid pruning intent")
        try:
            if digest_file(archive_fd, name) != (value["size"], value["sha256"]):
                raise ValueError("Pruning intent conflicts with archive")
            os.unlink(name, dir_fd=archive_fd)
            os.fsync(archive_fd)
        except FileNotFoundError:
            pass
        try:
            os.unlink(name + ".json", dir_fd=receipts_fd)
            os.fsync(receipts_fd)
        except FileNotFoundError:
            pass
        os.unlink(filename, dir_fd=archive_fd)
        os.fsync(archive_fd)
        log("retention_deleted", router=router, filename=name)


def maintain(archive_fd, receipts_fd, router, enabled=False, index_path=None, now=None, trigger=True, recover=True):
    pending = ".retention-pending.json"
    if enabled and trigger:
        try:
            exclusive_json(archive_fd, pending, dict(version=1))
        except FileExistsError:
            pass
    try:
        raw, info = read_small(archive_fd, pending)
        if info.st_uid != os.geteuid() or info.st_mode & 0o222 or decode_json(raw) != dict(version=1):
            raise ValueError("Unsafe retention trigger")
        retry = True
    except FileNotFoundError:
        retry = False
    # Idle cycles recover a prior successful archive's pruning, rather than
    # letting an incomplete/rejected incoming upload initiate deletion.
    prune_now = enabled and (trigger or retry)
    if retry and recover:
        finish_prunes(archive_fd, receipts_fd, router)
    records = inventory(archive_fd, receipts_fd)
    if any(row.get("router") != router for row in records):
        raise ValueError("Receipt belongs to a different router")
    keep = selection(records, now)
    remove = [row for row in records if row["filename"] not in keep]
    if prune_now:
        for row in remove:
            if digest_file(archive_fd, row["filename"]) != (row["size"], row["sha256"]):
                raise ValueError("Archive content disagrees with pruning receipt")
            intent = ".prune-" + hashlib.sha256(row["filename"].encode()).hexdigest() + ".json"
            exclusive_json(archive_fd, intent, {key: row[key] for key in ("filename", "size", "sha256")})
            finish_prunes(archive_fd, receipts_fd, router)
        records = [row for row in records if row["filename"] in keep]
        os.unlink(pending, dir_fd=archive_fd)
        os.fsync(archive_fd)
    if index_path is not None:
        atomic_json(
            index_path,
            dict(
                version=1,
                router=router,
                receipts={
                    row["filename"]: {key: row[key] for key in ("filename", "size", "sha256", "archived_at")}
                    for row in records
                },
            ),
            mode=0o644,
        )
    return dict(keep=sorted(keep), prune=[row["filename"] for row in remove])


def preview(root, routers):
    report = {}
    archive = os.open(root, DIR_FLAGS)
    try:
        with subdir(archive, "sftp", private=True) as namespace:
            for router in routers:
                try:
                    with subdir(namespace, router["name"], private=True) as directory:
                        with subdir(directory, ".receipts", private=True) as receipts:
                            # No recovery, index writes or deletion in preview mode.
                            report[router["name"]] = maintain(directory, receipts, router["name"], recover=False)
                except FileNotFoundError:
                    report[router["name"]] = dict(
                        keep=[],
                        prune=[],
                        unavailable="No complete managed receipt inventory; check for pending collector recovery",
                    )
    finally:
        os.close(archive)
    return report


if __name__ == "__main__":
    from common import load_routers

    print(json.dumps(preview("/archive", load_routers()), indent=2))
