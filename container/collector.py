"""Seal completed SFTP uploads into private, independently owned archive inodes."""

import contextlib
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from common import DONE, FILENAME, atomic_json, decode_json, directory, load_routers

READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def stamp():
    return datetime.now(timezone.utc).isoformat()


def snapshot(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def regular(fd):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("Expected a regular, unlinked-to file")
    return info


@contextlib.contextmanager
def subdir(parent, name, create=False, private=False):
    if create:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent)
        except FileExistsError:
            pass
    fd = os.open(name, DIR_FLAGS, dir_fd=parent)
    try:
        info = os.fstat(fd)
        if private and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
            raise ValueError("Archive directory has unsafe ownership or permissions")
        yield fd
    finally:
        os.close(fd)


def read_small(directory_fd, filename, limit=8192):
    fd = os.open(filename, READ_FLAGS, dir_fd=directory_fd)
    try:
        before = regular(fd)
        if before.st_size > limit:
            raise ValueError("Metadata exceeds size limit")
        data = os.read(fd, limit + 1)
        if len(data) > limit or snapshot(before) != snapshot(regular(fd)):
            raise ValueError("Metadata changed during read")
        return data, before
    finally:
        os.close(fd)


def write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("Short archive write")
        view = view[written:]


def exclusive_json(directory_fd, filename, value):
    temporary = ".tmp-" + secrets.token_hex(16)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=directory_fd)
    try:
        try:
            write_all(fd, (json.dumps(value, sort_keys=True) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.link(temporary, filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
        os.fsync(directory_fd)
    finally:
        os.unlink(temporary, dir_fd=directory_fd)


def digest_file(directory_fd, filename):
    fd = os.open(filename, READ_FLAGS, dir_fd=directory_fd)
    try:
        info = regular(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o222:
            raise ValueError("Existing archive has unsafe ownership or permissions")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        return info.st_size, digest.hexdigest()
    finally:
        os.close(fd)


def remove_if_unchanged(directory_fd, filename, original):
    try:
        current = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
        if snapshot(current) == snapshot(original):
            os.unlink(filename, dir_fd=directory_fd)
    except FileNotFoundError:
        pass


def seal(upload_fd, archive_fd, receipts_fd, router, marker):
    raw, marker_info = read_small(upload_fd, marker)
    manifest = decode_json(raw)
    if not isinstance(manifest, dict) or set(manifest) != {"version", "filename", "size"}:
        raise ValueError("Invalid completion manifest")
    name, size = manifest["filename"], manifest["size"]
    if (
        type(manifest["version"]) is not int
        or manifest["version"] != 1
        or not isinstance(name, str)
        or not FILENAME.fullmatch(name)
        or name.endswith(DONE)
        or marker != name + DONE
        or type(size) is not int
        or not 1 <= size <= router["max_bytes"]
    ):
        raise ValueError("Invalid completion filename or payload size")
    source = os.open(name, READ_FLAGS, dir_fd=upload_fd)
    temporary = ".tmp-" + secrets.token_hex(16)
    target = None
    try:
        before = regular(source)
        if before.st_size != size:
            raise ValueError("Payload size does not match completion manifest")
        target = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=archive_fd)
        digest = hashlib.sha256()
        remaining = size
        while remaining:
            block = os.read(source, min(1024 * 1024, remaining))
            if not block:
                raise ValueError("Payload was truncated")
            write_all(target, block)
            digest.update(block)
            remaining -= len(block)
        if os.read(source, 1) or snapshot(before) != snapshot(regular(source)):
            raise ValueError("Payload changed during archival")
        os.fsync(target)
        # link() exclusively publishes the new inode. It cannot replace a prior
        # archive, even after a crash or a simultaneous collector invocation.
        try:
            os.link(temporary, name, src_dir_fd=archive_fd, dst_dir_fd=archive_fd, follow_symlinks=False)
            os.fsync(archive_fd)
        except FileExistsError:
            # Recover an already-published file after restart; a different retry
            # with the same filename is a conflict, never a replacement.
            if digest_file(archive_fd, name) != (size, digest.hexdigest()):
                raise ValueError("Archive filename already exists with different content") from None
        receipt = dict(
            version=1, router=router["name"], filename=name, size=size, sha256=digest.hexdigest(), archived_at=stamp()
        )
        try:
            exclusive_json(receipts_fd, name + ".json", receipt)
        except FileExistsError:
            existing, _ = read_small(receipts_fd, name + ".json")
            existing = decode_json(existing)
            if not isinstance(existing, dict) or any(
                existing.get(key) != receipt[key] for key in ("version", "router", "filename", "size", "sha256")
            ):
                raise ValueError("Archive receipt conflicts with retained data") from None
            receipt = existing
        return receipt, before, marker_info
    finally:
        os.close(source)
        if target is not None:
            os.close(target)
            os.unlink(temporary, dir_fd=archive_fd)


def log(event, **fields):
    print(json.dumps(dict(event=event, timestamp=stamp(), **fields), sort_keys=True), flush=True)


def cleanup_staging(directory_fd):
    # Only our exact internal staging names; valid payload names never start '.'.
    # A published payload has another link and remains intact if its old stage
    # name survived a crash. Do this once per process, not during ongoing copies.
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            if not re.fullmatch(r"\.tmp-[0-9a-f]{32}", entry.name):
                continue
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid():
                os.unlink(entry.name, dir_fd=directory_fd)
    os.fsync(directory_fd)


class Collector:
    def __init__(
        self,
        routers,
        incoming="/incoming",
        archive="/archive",
        status="/run/mkbackup/collector-status.json",
        retention_enabled=False,
        receipt_index=None,
    ):
        self.routers = routers
        self.incoming, self.archive, self.status = Path(incoming), Path(archive), Path(status)
        self.last_success = {}
        self.cleaned = set()
        self.retention_enabled = retention_enabled
        self.receipt_index = Path(receipt_index) if receipt_index else None

    def cycle(self):
        storage = {}
        for label, path in (("incoming", self.incoming), ("archive", self.archive)):
            capacity = os.statvfs(path)
            storage[label] = dict(
                available_bytes=capacity.f_bavail * capacity.f_frsize, available_inodes=capacity.f_favail
            )
        state = dict(version=1, heartbeat=time.time(), healthy=True, routers={}, storage=storage)
        with contextlib.ExitStack() as stack:
            incoming = os.open(self.incoming, DIR_FLAGS)
            archive = os.open(self.archive, DIR_FLAGS)
            stack.callback(os.close, incoming)
            stack.callback(os.close, archive)
            root = stack.enter_context(subdir(archive, "sftp", create=True, private=True))
            for router in self.routers:
                name = router["name"]
                report = dict(
                    pending_count=0,
                    pending_bytes=0,
                    completion_count=0,
                    scan_truncated=False,
                    last_success=None,
                    overdue=router["enabled"],
                    last_error=None,
                    enabled=router["enabled"],
                )
                state["routers"][name] = report
                try:
                    destination = stack.enter_context(subdir(root, name, create=True, private=True))
                    receipts = stack.enter_context(subdir(destination, ".receipts", create=True, private=True))
                    if name not in self.cleaned:
                        cleanup_staging(destination)
                        cleanup_staging(receipts)
                        self.cleaned.add(name)
                    if name not in self.last_success:
                        try:
                            raw, _ = read_small(destination, ".last-success.json")
                            self.last_success[name] = decode_json(raw)
                        except FileNotFoundError:
                            pass
                    with subdir(incoming, name) as home, subdir(home, "upload") as upload:
                        names = []
                        with os.scandir(upload) as entries:
                            for entry in entries:
                                if len(names) >= 10000:
                                    report["scan_truncated"] = True
                                    break
                                names.append(entry.name)
                                info = entry.stat(follow_symlinks=False)
                                if stat.S_ISREG(info.st_mode) and not entry.name.endswith(DONE):
                                    report["pending_count"] += 1
                                    report["pending_bytes"] += info.st_size
                        for marker in names:
                            if not marker.endswith(DONE):
                                continue
                            report["completion_count"] += 1
                            if not router["enabled"]:
                                continue
                            try:
                                receipt, payload_info, marker_info = seal(upload, destination, receipts, router, marker)
                                # Persist the status summary before deleting incoming
                                # files. A crash at any stage is safe to retry.
                                previous = self.last_success.get(name)
                                if previous is None or receipt["archived_at"] > previous["archived_at"]:
                                    self.last_success[name] = receipt
                                atomic_json(
                                    self.archive / "sftp" / name / ".last-success.json", self.last_success[name]
                                )
                                self.maintain(destination, receipts, name, trigger=True)
                                remove_if_unchanged(upload, receipt["filename"], payload_info)
                                remove_if_unchanged(upload, marker, marker_info)
                                log("archived", **receipt)
                            except (ValueError, OSError) as error:
                                report["last_error"] = type(error).__name__ + ": " + str(error)
                                log("archive_rejected", router=name, marker=marker, error=report["last_error"])
                                if isinstance(error, OSError) and error.errno not in (
                                    errno.ENOENT,
                                    errno.ELOOP,
                                    errno.ENOTDIR,
                                ):
                                    state["healthy"] = False
                    # Recover pruning and refresh metadata even with no new upload.
                    self.maintain(destination, receipts, name)
                except FileNotFoundError:
                    # SFTP may still be provisioning this router's directory.
                    pass
                except (OSError, ValueError) as error:
                    report["last_error"] = type(error).__name__ + ": " + str(error)
                    state["healthy"] = False
                    log("collector_error", router=name, error=report["last_error"])
                report["last_success"] = self.last_success.get(name)
                if report["last_success"]:
                    last = datetime.fromisoformat(report["last_success"]["archived_at"]).timestamp()
                    report["overdue"] = (
                        router["enabled"] and time.time() - last > router["expected_interval_seconds"] * 1.5
                    )
        state["heartbeat"] = time.time()
        atomic_json(self.status, state)
        return state

    def maintain(self, destination, receipts, name, trigger=False):
        if self.retention_enabled or self.receipt_index is not None:
            from retention import maintain

            maintain(
                destination,
                receipts,
                name,
                enabled=self.retention_enabled,
                index_path=self.receipt_index / (name + ".json") if self.receipt_index else None,
                trigger=trigger,
            )


def main():
    os.umask(0o077)
    routers = load_routers()
    interval = int(os.environ.get("COLLECT_INTERVAL_SECONDS", "2"))
    if not 1 <= interval <= 60:
        raise ValueError("Invalid collector interval")
    directory("/run/mkbackup", 0o700)
    # Only the volume's top-level ownership is normalized; legacy backups are
    # never traversed, changed, or exposed in SFTP chroots.
    directory("/archive")
    directory("/receipts", 0o755)
    retention = os.environ.get("RETENTION_ENABLED", "0")
    if retention not in ("0", "1"):
        raise ValueError("RETENTION_ENABLED must be 0 or 1")
    collector = Collector(routers, retention_enabled=retention == "1", receipt_index="/receipts")
    log("collector_started", routers=len(routers))
    while True:
        try:
            generation = None
            if os.environ.get("ROUTERS_SNAPSHOT"):
                from common import load_snapshot

                generation, collector.routers = load_snapshot()
            state = collector.cycle()
            if generation is not None:
                atomic_json(
                    "/acks/collector.json",
                    dict(generation=generation, healthy=state["healthy"], heartbeat=time.time()),
                    mode=0o644,
                )
        except (OSError, ValueError) as error:
            log("collector_storage_error", error=type(error).__name__)
            atomic_json(collector.status, dict(version=1, heartbeat=time.time(), healthy=False, routers={}))
        time.sleep(interval)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError):
        sys.exit("Collector startup refused: check registry, interval and volume permissions")
