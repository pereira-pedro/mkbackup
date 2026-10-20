import concurrent.futures
import hashlib
import io
import json
import secrets
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "container"))
from admin_sessions import COOKIE, Sessions
from admin_web import Application
from control_rpc import Client, ControlError
from enrollment import Store
from provisioner import Provisioner, Server


class ProvisionerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        cls.host_key = (
            rsa.generate_private_key(public_exponent=65537, key_size=3072)
            .public_key()
            .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
            .decode()
        )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("config", "ftp", "acks"):
            (self.root / name).mkdir()
        self.key = self.root / "key"
        self.key.write_bytes(secrets.token_bytes(32))
        self.store = Store(self.root / "state", self.key)
        self.engine = Provisioner(
            self.store,
            dict(version=2, routers=[]),
            {},
            self.host_key,
            self.root / "config",
            self.root / "ftp",
            self.root / "acks",
            "https://backup.example.com",
        )
        self.owner = hashlib.sha256(b"session").hexdigest()
        self.spec = dict(name="router1", major=6, host="203.0.113.1", port=2157, job_owner="admin")

    def submit(self, action="create", spec=None, request=None):
        return self.engine.enqueue(spec or self.spec, self.owner, request or secrets.token_hex(32), action)["id"]

    def complete(self, job):
        with mock.patch.object(self.engine, "wait_applied"):
            self.engine.process_one()
        self.assertEqual(self.engine.job(job, self.owner)["state"], "ready")
        return self.engine.instructions(job, self.owner)

    def test_credentials_encrypted_commands_once_and_delivery_locks_reissue(self):
        job = self.submit()
        result = self.complete(job)
        raw = (self.root / "state/enrollment.sqlite3").read_bytes()
        self.assertNotIn(result["token"].encode(), raw)
        self.assertNotIn(b"BEGIN RSA PRIVATE KEY", raw)
        with self.assertRaises(ControlError):
            self.engine.instructions(job, self.owner)
        self.assertTrue(self.store.redeem(result["token"], 6))
        with self.assertRaisesRegex(ControlError, "already delivered"):
            self.submit("reissue")

    def test_reissue_revokes_previous_token_preserves_uid_and_expired_unused_is_eligible(self):
        first = self.complete(self.submit())
        uid = self.engine.registry()[1][0]["uid"]
        with self.store.connect() as db:
            db.execute("UPDATE deployments SET expires=?", (time.time() - 1,))
        self.engine.health()
        job = self.submit("reissue")
        with self.assertRaises(ValueError):
            self.store.redeem(first["token"])
        self.complete(job)
        self.assertEqual(self.engine.registry()[1][0]["uid"], uid)

    def test_duplicate_submissions_and_concurrent_uid_allocation(self):
        request = secrets.token_hex(32)
        job = self.submit(request=request)
        self.assertEqual(self.submit(request=request), job)
        with self.assertRaises(ControlError):
            self.submit()

        def add(index):
            return self.submit(spec=dict(self.spec, name="r" + str(index)))

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(add, range(6)))
        uids = [row["uid"] for row in self.engine.registry()[1]]
        self.assertEqual(len(uids), len(set(uids)))

    def test_redemption_and_reissue_cannot_both_win(self):
        first = self.complete(self.submit())

        def redeem():
            try:
                self.store.redeem(first["token"])
                return True
            except ValueError:
                return False

        def reissue():
            try:
                self.submit("reissue")
                return True
            except ControlError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = [pool.submit(action) for action in (redeem, reissue)]
            self.assertEqual(sum(result.result() for result in results), 1)

    def test_missing_ack_fails_without_issuing_token_and_restart_marks_interrupted_job(self):
        job = self.submit()
        with mock.patch.object(self.engine, "wait_applied", side_effect=ControlError("Refresh unavailable", 503)):
            self.engine.process_one()
        self.assertEqual(self.engine.job(job, self.owner)["state"], "failed")
        self.assertEqual(self.store.listing(), [])
        retry = self.submit("reissue")
        with self.store.connect() as db:
            db.execute("UPDATE jobs SET state='running' WHERE id=?", (retry,))
        restarted = Provisioner(
            self.store,
            dict(version=2, routers=[]),
            {},
            self.host_key,
            self.root / "config",
            self.root / "ftp",
            self.root / "acks",
            "https://backup.example.com",
        )
        self.assertEqual(restarted.job(retry, self.owner)["state"], "failed")
        self.assertEqual(restarted.registry()[1][0]["uid"], 10000)

    def test_profiles_hosts_owners_and_cross_session_access_are_validated(self):
        for values in (
            dict(name="../root"),
            dict(major=True),
            dict(host="host;evil"),
            dict(port=0),
            dict(job_owner='admin";evil'),
        ):
            with self.subTest(values=values), self.assertRaises(ControlError):
                self.submit(spec=dict(self.spec, **values))
        job = self.submit()
        with self.assertRaises(ControlError):
            self.engine.job(job, "a" * 64)
        with self.assertRaises(ControlError):
            self.engine.enqueue(self.spec, self.owner, secrets.token_hex(32), "rotate")

    def test_socket_roles_cannot_escalate_to_cli_or_admin(self):
        import threading

        for role in ("public", "admin"):
            server = Server(self.root / (role + ".sock"), role, self.engine)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                client = Client(self.root / (role + ".sock"))
                self.assertTrue(client.request("health")["ready"])
                for operation, args in (
                    ("registry", {}),
                    ("mutate", dict(action="disable", name="router1")),
                    ("rotate", dict(spec=self.spec, owner=self.owner, request="a" * 64)),
                ):
                    with self.assertRaises(ControlError) as error:
                        client.request(operation, **args)
                    self.assertEqual(error.exception.status, 403)
                if role == "public":
                    with self.assertRaises(ControlError):
                        client.request("create", spec=self.spec, owner=self.owner, request="a" * 64)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_v7_generation_produces_private_pem_only_inside_encrypted_installer(self):
        job = self.submit(spec=dict(self.spec, major=7, port=15100))
        result = self.complete(job)
        script = self.store.redeem(result["token"], 7)
        self.assertIn(b"BEGIN RSA PRIVATE KEY", script)
        self.assertIn(b"sftp-known-hosts-ignore=no", script)
        snapshots = (self.root / "config/routers.json").read_bytes() + (self.root / "ftp/passwords.json").read_bytes()
        self.assertNotIn(b"PRIVATE KEY", snapshots)
        self.assertNotIn(b"BEGIN RSA PRIVATE KEY", (self.root / "state/enrollment.sqlite3").read_bytes())

    def test_imported_routers_are_locked_and_snapshot_generations_match(self):
        with self.store.connect() as db:
            db.execute("DELETE FROM registry")
        seed = dict(version=2, routers=[dict(name="legacy", uid=12345, keys=[], transport="ftp", enabled=False)])
        engine = Provisioner(
            self.store, seed, {}, self.host_key, self.root / "config", self.root / "ftp", self.root / "acks"
        )
        self.assertEqual(engine.registry()[1][0]["uid"], 12345)
        with self.assertRaises(ControlError):
            engine.enqueue(dict(self.spec, name="legacy"), self.owner, secrets.token_hex(32), "reissue")
        self.assertEqual(
            json.loads((self.root / "config/routers.json").read_text())["generation"],
            json.loads((self.root / "ftp/passwords.json").read_text())["generation"],
        )


class EnrollmentWebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.sessions = Sessions(self.temp.name, secrets.token_urlsafe(32))
        self.control = mock.Mock()
        self.app = Application(self.sessions, mock.Mock(), self.control)
        self.token, _ = self.sessions.create(authenticated=True)
        self.csrf = self.sessions.csrf_token(self.token)

    def request(self, path, method="GET", data=None, token=True, query=""):
        body = urlencode(data or {}).encode()
        env = dict(
            PATH_INFO=path,
            REQUEST_METHOD=method,
            QUERY_STRING=query,
            CONTENT_TYPE="application/x-www-form-urlencoded",
            CONTENT_LENGTH=str(len(body)),
            HTTP_COOKIE=f"{COOKIE}={self.token}" if token else "",
            **{"wsgi.input": io.BytesIO(body)},
        )
        result = []

        def start(status, headers):
            result.extend([int(status.split()[0]), dict(headers)])

        result.append(b"".join(self.app(env, start)))
        return result

    def test_enrollment_requires_authentication_and_csrf_and_is_idempotent(self):
        self.assertEqual(self.request("/admin/enroll", token=False)[0], 303)
        self.control.request.assert_not_called()
        form = dict(
            csrf="wrong",
            major=6,
            action="create",
            request="a" * 64,
            name="r1",
            host="203.0.113.1",
            port=2157,
            job_owner="admin",
        )
        self.assertEqual(self.request("/admin/enroll", "POST", form)[0], 403)
        self.control.request.assert_not_called()
        form["csrf"] = self.csrf
        self.control.request.return_value = dict(id="b" * 64)
        first = self.request("/admin/enroll", "POST", form)
        self.assertEqual(first[0], 303)
        self.assertEqual(first[1]["Location"], "/admin/enrollments/" + "b" * 64)
        self.assertNotIn(b"Bearer", first[2])

    def test_forms_status_and_instructions_are_escaped_and_never_cached(self):
        self.control.request.return_value = dict(
            routers=[],
            defaults=dict(host="203.0.113.1", ftp_port=2157, sftp_port=15100, base_url="https://backup.example.com"),
        )
        status, headers, body = self.request("/admin/enroll", query="major=7")
        self.assertEqual(status, 200)
        self.assertIn(b"15100", body)
        self.assertIn("no-store", headers["Cache-Control"])
        self.control.request.return_value = dict(
            token="s" * 43, expires_at=time.time() + 600, base_url="https://backup.example.com", router="r1"
        )
        path = "/admin/enrollments/" + "a" * 64 + "/instructions"
        self.assertEqual(self.request(path)[0], 405)
        status, headers, body = self.request(path, "POST", dict(csrf=self.csrf))
        self.assertEqual(status, 200)
        self.assertIn(b"Bearer", body)
        self.assertIn("no-store", headers["Cache-Control"])
        self.assertNotIn("Location", headers)
        self.assertEqual(self.request("/admin/enroll", query="major=x")[0], 400)
