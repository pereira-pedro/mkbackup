import hashlib
import io
import json
import os
import secrets
import sys
import tempfile
import threading
import tracemalloc
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "container"))
from admin_sessions import COOKIE, IDLE, LIFETIME, Sessions
from admin_web import Application
from archive_reader import Archive, Server
from archive_rpc import ArchiveError, Client


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.password = secrets.token_urlsafe(32)
        self.sessions = Sessions(self.temp.name, self.password)

    def test_password_is_required_and_constant_time_comparison_is_used(self):
        for value in (None, "", "short", "a" * 1025, "a" * 20 + "\0"):
            with self.subTest(value=value), mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(ValueError):
                    Sessions(self.temp.name, value)
        self.assertTrue(self.sessions.check_password(self.password))
        with mock.patch("admin_sessions.hmac.compare_digest", wraps=__import__("hmac").compare_digest) as compare:
            self.assertFalse(self.sessions.check_password("wrong"))
            compare.assert_called_once()

    def test_tokens_are_hashed_and_sessions_shared_across_workers(self):
        token, csrf = self.sessions.create(authenticated=True, now=100)
        raw = self.sessions.path.read_bytes()
        for secret in (token, csrf, self.password):
            self.assertNotIn(secret.encode(), raw)
        other_worker = Sessions(self.temp.name, self.password)
        session = other_worker.get(token, now=101)
        self.assertTrue(session["authenticated"])
        self.assertTrue(other_worker.csrf_valid(session, csrf))
        self.assertFalse(other_worker.csrf_valid(session, "x" * 43))
        new, _ = other_worker.create(authenticated=True, replace=token, now=102)
        self.assertIsNone(self.sessions.get(token, now=103))
        self.assertTrue(self.sessions.get(new, now=103)["authenticated"])

    def test_expiry_logout_and_preauth_lifetime(self):
        token, _ = self.sessions.create(authenticated=True, now=100)
        self.assertIsNone(self.sessions.get(token, now=100 + IDLE))
        token, _ = self.sessions.create(authenticated=True, now=100)
        for now in range(100 + 1000, 100 + LIFETIME, 1000):
            self.assertTrue(self.sessions.get(token, now=now))
        self.assertIsNone(self.sessions.get(token, now=100 + LIFETIME))
        token, _ = self.sessions.create(now=100)
        self.assertIsNone(self.sessions.get(token, now=700))
        token, _ = self.sessions.create(authenticated=True)
        self.sessions.revoke(token)
        self.assertIsNone(self.sessions.get(token))

    def test_csrf_key_is_random_per_store_and_independent_of_password(self):
        token, csrf = self.sessions.create()
        other_worker = Sessions(self.temp.name, self.password)
        self.assertEqual(other_worker.csrf_token(token), csrf)
        with tempfile.TemporaryDirectory() as directory:
            other_store = Sessions(directory, self.password)
            self.assertNotEqual(other_store.csrf_token(token), csrf)
            self.assertNotEqual(other_store.csrf_key, self.sessions.csrf_key)

    def test_session_store_is_bounded_without_evicting_authenticated_users(self):
        token, _ = self.sessions.create(authenticated=True, now=100)
        with self.sessions.connect() as db:
            db.executemany(
                "INSERT INTO sessions VALUES (?,?,?,?,?)", [(f"fake-{i}", "csrf", 100, 100, 0) for i in range(1100)]
            )
        self.sessions.create(now=101)
        with self.sessions.connect() as db:
            self.assertLessEqual(db.execute("SELECT count(*) FROM sessions").fetchone()[0], 1025)
        self.assertTrue(self.sessions.get(token, now=102)["authenticated"])


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = Archive(self.root / "archive", owner=os.geteuid())
        self.make_router("alice")

    def make_router(self, name):
        receipts = self.root / "archive/sftp" / name / ".receipts"
        receipts.mkdir(parents=True, mode=0o700, exist_ok=True)
        return receipts.parent

    def put(
        self, name="alice-20261020030509.rsc", content=b"safe export", router="alice", when="2026-10-20T03:05:10+00:00"
    ):
        directory = self.make_router(router)
        path = directory / name
        path.write_bytes(content)
        path.chmod(0o400)
        receipt = dict(
            version=1,
            router=router,
            filename=name,
            size=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
            archived_at=when,
        )
        target = directory / ".receipts" / (name + ".json")
        target.write_text(json.dumps(receipt))
        target.chmod(0o400)
        return path, target

    def start_server(self):
        path = self.root / "reader.sock"
        server = Server(path, self.archive)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return Client(path)

    def test_search_pagination_empty_router_and_receipt_ordering(self):
        self.put("alice-1.rsc", when="2026-01-01T01:00:00+00:00")
        self.put()
        self.make_router("empty")
        for i in range(51):
            self.make_router(f"router-{i:02}")
        self.assertEqual(self.archive.routers("ALIC", 1)["items"][0]["count"], 2)
        self.assertEqual(self.archive.routers("missing", 1)["total"], 0)
        self.assertEqual(len(self.archive.routers("", 1)["items"]), 50)
        self.assertEqual(len(self.archive.routers("", 2)["items"]), 3)
        self.assertEqual(self.archive.files("empty", 1)["items"], [])
        rows = self.archive.files("alice", 1)["items"]
        self.assertEqual([r["filename"] for r in rows], ["alice-20261020030509.rsc", "alice-1.rsc"])
        for i in range(51):
            self.put(f"old-{i}.rsc")
        self.assertEqual(len(self.archive.files("alice", 1)["items"]), 50)
        self.assertEqual(len(self.archive.files("alice", 2)["items"]), 3)

    def test_only_receipt_backed_regular_managed_files_are_visible(self):
        self.put()
        (self.root / "archive/legacy.backup").write_bytes(b"legacy")
        (self.root / "archive/sftp/alice/pending.rsc").write_bytes(b"pending")
        self.assertEqual(self.archive.files("alice", 1)["total"], 1)
        for router, name in (
            ("../alice", "anything"),
            ("alice", "../legacy.backup"),
            ("alice", ".last-success.json"),
            ("alice", "pending.rsc"),
        ):
            with self.subTest(router=router, name=name), self.assertRaises((ArchiveError, OSError)):
                self.archive.download(router, name)
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / "archive/sftp/link").symlink_to(outside, target_is_directory=True)
        self.assertNotIn("link", [r["name"] for r in self.archive.routers("", 1)["items"]])

    def test_download_rejects_symlinks_hardlinks_fifo_mutable_files_and_corruption(self):
        for kind in ("symlink", "hardlink", "fifo", "mutable", "content", "receipt", "wrong-router"):
            with self.subTest(kind=kind):
                path, receipt = self.put(name=kind + ".rsc")
                if kind == "symlink":
                    path.unlink()
                    path.symlink_to(receipt)
                elif kind == "hardlink":
                    os.link(path, path.with_suffix(".link"))
                elif kind == "fifo":
                    path.unlink()
                    os.mkfifo(path, 0o400)
                elif kind == "mutable":
                    path.chmod(0o600)
                elif kind == "content":
                    path.chmod(0o600)
                    path.write_bytes(b"bad! export")
                    path.chmod(0o400)
                elif kind == "receipt":
                    receipt.chmod(0o600)
                    receipt.write_text("not json")
                    receipt.chmod(0o400)
                else:
                    value = json.loads(receipt.read_text())
                    value["router"] = "bob"
                    receipt.chmod(0o600)
                    receipt.write_text(json.dumps(value))
                    receipt.chmod(0o400)
                with self.assertRaises((ArchiveError, OSError, ValueError)):
                    self.archive.download("alice", path.name)

    def test_open_download_survives_pruning_and_path_replacement(self):
        path, receipt = self.put()
        fd, metadata = self.archive.download("alice", path.name)
        try:
            path.unlink()
            receipt.unlink()
            path.write_bytes(b"replacement")
            self.assertEqual(os.read(fd, 1024), b"safe export")
            self.assertEqual(metadata["size"], 11)
        finally:
            os.close(fd)
        with self.assertRaises(FileNotFoundError):
            self.archive.download("alice", path.name)

    def test_unix_protocol_and_100_mib_download_have_bounded_memory(self):
        path = self.make_router("large") / "large-20261020030509.rsc"
        block = b"x" * (64 * 1024)
        digest = hashlib.sha256()
        with path.open("wb") as output:
            for _ in range(1600):
                output.write(block)
                digest.update(block)
        path.chmod(0o400)
        receipt = dict(
            version=1,
            router="large",
            filename=path.name,
            size=100 * 1024 * 1024,
            sha256=digest.hexdigest(),
            archived_at="2026-10-20T00:00:00+00:00",
        )
        target = path.parent / ".receipts" / (path.name + ".json")
        target.write_text(json.dumps(receipt))
        target.chmod(0o400)
        client = self.start_server()
        self.assertEqual(client.request("health"), dict(ready=True))
        tracemalloc.start()
        try:
            stream = client.request("download", router="large", filename=path.name)
            received = hashlib.sha256()
            size = 0
            for chunk in stream:
                self.assertLessEqual(len(chunk), 64 * 1024)
                received.update(chunk)
                size += len(chunk)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(size, receipt["size"])
        self.assertEqual(received.hexdigest(), receipt["sha256"])
        self.assertLess(peak, 4 * 1024 * 1024)
        with self.assertRaises(ArchiveError) as error:
            client.request("download", router="large", filename="../legacy.backup")
        self.assertEqual(error.exception.status, 404)

    def test_protocol_rejects_unknown_operations_and_unbounded_requests(self):
        client = self.start_server()
        for operation, params in (
            ("read", dict(path="/etc/passwd")),
            ("files", dict(router="alice", page=0)),
            ("files", dict(router="alice", page=True)),
            ("routers", dict(query="x" * 129)),
            ("health", dict(path="/archive")),
        ):
            with self.subTest(operation=operation), self.assertRaises(ArchiveError) as rejected:
                client.request(operation, **params)
            self.assertEqual(rejected.exception.status, 400)


class WebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.password = secrets.token_urlsafe(32)
        self.sessions = Sessions(self.temp.name, self.password)
        self.reader = mock.Mock()
        self.app = Application(self.sessions, self.reader)

    def request(self, path="/admin/", token=None, method="GET", data=None, query=""):
        body = urlencode(data or {}).encode()
        environ = dict(
            PATH_INFO=path,
            REQUEST_METHOD=method,
            QUERY_STRING=query,
            CONTENT_TYPE="application/x-www-form-urlencoded",
            CONTENT_LENGTH=str(len(body)),
            HTTP_COOKIE=f"{COOKIE}={token}" if token else "",
            **{"wsgi.input": io.BytesIO(body)},
        )
        result = []

        def start(status, headers):
            result.extend([int(status.split()[0]), dict(headers)])

        iterator = self.app(environ, start)
        try:
            result.append(b"".join(iterator))
        finally:
            if hasattr(iterator, "close"):
                iterator.close()
        return result

    def login(self):
        token, csrf = self.sessions.create()
        status, headers, _ = self.request("/admin/login", token, "POST", dict(csrf=csrf, password=self.password))
        self.assertEqual(status, 303)
        fresh = headers["Set-Cookie"].split(";", 1)[0].split("=", 1)[1]
        self.assertIsNone(self.sessions.get(token))
        return fresh

    def test_login_logout_csrf_cookies_and_secret_free_errors(self):
        status, headers, body = self.request("/admin/login")
        self.assertEqual(status, 200)
        for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/admin/"):
            self.assertIn(flag, headers["Set-Cookie"])
        self.assertNotIn("Domain=", headers["Set-Cookie"])
        self.assertIn("no-store", headers["Cache-Control"])
        token, csrf = self.sessions.create()
        self.assertEqual(
            self.request("/admin/login", token, "POST", dict(csrf="wrong", password=self.password))[0], 403
        )
        status, _, body = self.request("/admin/login", token, "POST", dict(csrf=csrf, password="wrong"))
        self.assertEqual(status, 401)
        self.assertNotIn(self.password.encode(), body)
        token = self.login()
        csrf = self.sessions.csrf_token(token)
        self.assertEqual(self.request("/admin/logout", token, "POST", dict(csrf="wrong"))[0], 403)
        self.assertEqual(self.request("/admin/logout", token, "POST", dict(csrf=csrf))[0], 303)
        self.assertIsNone(self.sessions.get(token))

    def test_unauthenticated_routes_never_call_reader(self):
        self.assertEqual(self.request()[0], 303)
        self.assertEqual(self.request("/admin/routers/alice/files/alice-1.rsc/download")[0], 401)
        self.reader.request.assert_not_called()

    def test_search_escaping_empty_files_and_query_validation(self):
        token = self.login()
        self.reader.request.return_value = dict(items=[], page=1, total=0)
        status, _, body = self.request(token=token, query=urlencode(dict(q='<script>alert("x")</script>')))
        self.assertEqual(status, 200)
        self.assertNotIn(b"<script>", body)
        self.assertIn(b"&lt;script&gt;", body)
        self.assertIn(b"No routers found", body)
        status, _, body = self.request("/admin/routers/alice", token)
        self.assertEqual(status, 200)
        self.assertIn(b"No available backups", body)
        for query in ("page=0", "page=hello", "page=1&page=2", "x=1"):
            self.assertEqual(self.request(token=token, query=query)[0], 400)

    def test_download_errors_are_clear_without_payload_or_filesystem_details(self):
        token = self.login()
        for status in (404, 409, 503):
            self.reader.request.side_effect = ArchiveError(status, "Backup unavailable")
            response, _, body = self.request("/admin/routers/alice/files/alice-1.rsc/download", token)
            self.assertEqual(response, status)
            self.assertNotIn(b"/archive", body)
        self.reader.request.side_effect = OSError("/sensitive/path")
        response, _, body = self.request(token=token)
        self.assertEqual(response, 503)
        self.assertNotIn(b"/sensitive/path", body)


if __name__ == "__main__":
    unittest.main()
