"""Read-only managed archive broker. No TCP listener, credentials or mutations."""

import hashlib
import os
import re
import socketserver
import stat
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from archive_rpc import CHUNK, SOCKET, ArchiveError, receive, send
from collector import DIR_FLAGS, READ_FLAGS, read_small, subdir
from common import FILENAME, NAME, decode_json


class Archive:
    def __init__(self, path="/archive", owner=0):
        self.path, self.owner = str(path), owner

    @contextmanager
    def namespace(self):
        root = os.open(self.path, DIR_FLAGS)
        try:
            with subdir(root, "sftp", private=True) as namespace:
                yield namespace
        finally:
            os.close(root)

    def check_file(self, info, size=None):
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != self.owner
            or info.st_mode & 0o222
            or (size is not None and info.st_size != size)
        ):
            raise ArchiveError(409, "Archive integrity check failed")

    def receipt(self, receipts, router, name):
        raw, info = read_small(receipts, name + ".json")
        self.check_file(info)
        value = decode_json(raw)
        if (
            not isinstance(value, dict)
            or type(value.get("version")) is not int
            or value["version"] != 1
            or value.get("router") != router
            or value.get("filename") != name
            or type(value.get("size")) is not int
            or value["size"] < 1
            or not isinstance(value.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"])
            or not isinstance(value.get("archived_at"), str)
        ):
            raise ArchiveError(409, "Archive integrity check failed")
        when = datetime.fromisoformat(value["archived_at"])
        if when.tzinfo is None:
            raise ArchiveError(409, "Archive integrity check failed")
        return dict(
            filename=name,
            size=value["size"],
            sha256=value["sha256"],
            archived_at=when.astimezone(timezone.utc).isoformat(),
        )

    @contextmanager
    def router(self, name):
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise ArchiveError(404, "Router not found")
        with self.namespace() as namespace, subdir(namespace, name, private=True) as directory:
            with subdir(directory, ".receipts", private=True) as receipts:
                yield directory, receipts

    def records(self, router, directory, receipts):
        records = []
        with os.scandir(receipts) as entries:
            for count, entry in enumerate(entries):
                if count >= 10000:
                    raise ArchiveError(503, "Archive inventory exceeds scan limit")
                if entry.name.startswith(".tmp-"):
                    continue
                name = entry.name[:-5] if entry.name.endswith(".json") else ""
                if not FILENAME.fullmatch(name) or name.endswith(".done.json"):
                    raise ArchiveError(409, "Archive integrity check failed")
                try:
                    record = self.receipt(receipts, router, name)
                    self.check_file(os.stat(name, dir_fd=directory, follow_symlinks=False), record["size"])
                    records.append(record)
                except FileNotFoundError:
                    # Retention can remove a payload or receipt during a listing.
                    continue
        return sorted(records, key=lambda row: (row["archived_at"], row["filename"]), reverse=True)

    def files(self, router, page):
        with self.router(router) as (directory, receipts):
            rows = self.records(router, directory, receipts)
        return dict(items=rows[(page - 1) * 50 : page * 50], total=len(rows), page=page)

    def routers(self, query, page):
        rows = []
        try:
            with self.namespace() as namespace, os.scandir(namespace) as entries:
                for count, entry in enumerate(entries):
                    if count >= 1000:
                        raise ArchiveError(503, "Router inventory exceeds scan limit")
                    if not NAME.fullmatch(entry.name) or not entry.is_dir(follow_symlinks=False):
                        continue
                    if query.casefold() not in entry.name.casefold():
                        continue
                    try:
                        with self.router(entry.name) as (directory, receipts):
                            records = self.records(entry.name, directory, receipts)
                        rows.append(
                            dict(
                                name=entry.name,
                                count=len(records),
                                latest=records[0]["archived_at"] if records else None,
                                error=False,
                            )
                        )
                    except FileNotFoundError:
                        continue
                    except (OSError, ValueError, ArchiveError):
                        rows.append(dict(name=entry.name, count=None, latest=None, error=True))
        except FileNotFoundError:
            pass
        rows.sort(key=lambda row: row["name"])
        return dict(items=rows[(page - 1) * 50 : page * 50], total=len(rows), page=page)

    def download(self, router, name):
        if not isinstance(name, str) or not FILENAME.fullmatch(name) or name.endswith(".done.json"):
            raise ArchiveError(404, "Backup not found")
        with self.router(router) as (directory, receipts):
            record = self.receipt(receipts, router, name)
            fd = os.open(name, READ_FLAGS, dir_fd=directory)
        try:
            before = os.fstat(fd)
            self.check_file(before, record["size"])
            digest = hashlib.sha256()
            while True:
                block = os.read(fd, CHUNK)
                if not block:
                    break
                digest.update(block)
            after = os.fstat(fd)
            # Unlinking an already-open immutable payload during pruning is safe.
            if (
                digest.hexdigest() != record["sha256"]
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
            ):
                raise ArchiveError(409, "Archive integrity check failed")
            os.lseek(fd, 0, os.SEEK_SET)
            return fd, record
        except Exception:
            os.close(fd)
            raise


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(60)
        started = False
        try:
            value = receive(self.request, limit=4096)
            operation = value.pop("operation", None)
            if operation == "health" and not value:
                data = dict(ready=True)
            elif operation in ("routers", "files"):
                page = value.pop("page", 1)
                if type(page) is not int or not 1 <= page <= 1000000:
                    raise ArchiveError(400, "Invalid page")
                key = "query" if operation == "routers" else "router"
                argument = value.pop(key, "" if key == "query" else None)
                if value or not isinstance(argument, str) or len(argument) > 128:
                    raise ArchiveError(400, "Invalid archive request")
                data = (
                    self.server.archive.routers(argument, page)
                    if operation == "routers"
                    else self.server.archive.files(argument, page)
                )
            elif operation == "download" and set(value) == {"router", "filename"}:
                fd, data = self.server.archive.download(value["router"], value["filename"])
                try:
                    send(self.request, dict(status=200, data=data))
                    started = True
                    while True:
                        block = os.read(fd, CHUNK)
                        if not block:
                            break
                        self.request.sendall(block)
                finally:
                    os.close(fd)
                return
            else:
                raise ArchiveError(400, "Invalid archive request")
            send(self.request, dict(status=200, data=data))
        except Exception as error:
            if not started:
                status, message = 503, "Archive unavailable"
                if isinstance(error, ArchiveError):
                    status, message = error.status, error.message
                elif isinstance(error, FileNotFoundError):
                    status, message = 404, "Backup or router not found"
                elif isinstance(error, (ValueError, OSError)):
                    status, message = 409, "Archive integrity check failed"
                try:
                    send(self.request, dict(status=status, error=message))
                except OSError:
                    pass


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, path=SOCKET, archive=None):
        self.archive = archive or Archive()
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(str(path), Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


if __name__ == "__main__":
    os.umask(0o007)
    path = Path(SOCKET)
    if path.exists() or path.is_symlink():
        if not stat.S_ISSOCK(path.lstat().st_mode):
            raise SystemExit("Archive socket path is not a socket")
        path.unlink()
    with Server() as server:
        path.chmod(0o660)
        server.serve_forever()
