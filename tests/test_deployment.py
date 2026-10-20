import concurrent.futures
import importlib.util
import io
import json
import os
import secrets
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "container"))
sys.path.insert(0, str(ROOT / "scripts"))
import collector
import retention
import routeros
from common import parse_routers

try:
    import enrollment
    import web
except ModuleNotFoundError as error:
    if error.name != "cryptography":
        raise
    enrollment = None


@unittest.skipIf(enrollment is None, "Run in the application image for python3-cryptography")
class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / "key"
        self.key.write_bytes(secrets.token_bytes(32))
        self.store = enrollment.Store(self.root / "state", self.key)
        self.status = secrets.token_urlsafe(32)
        web.store = self.store
        self.addCleanup(setattr, web, "store", None)

    def issue(self, **kwargs):
        return self.store.create("alice", 6, b"private installer with unique credential", self.status, **kwargs)

    def request(self, path="/", token=None, method="GET", query=""):
        result = []

        def start(status, headers):
            result.extend([status, dict(headers)])

        body = b"".join(
            web.application(
                dict(
                    REQUEST_METHOD=method,
                    PATH_INFO=path,
                    QUERY_STRING=query,
                    HTTP_AUTHORIZATION="Bearer " + token if token else "",
                ),
                start,
            )
        )
        return result[0], result[1], body

    def test_encrypted_storage_single_download_and_profile_binding(self):
        issued = self.issue()
        database = (self.root / "state/enrollment.sqlite3").read_bytes()
        self.assertNotIn(issued["token"].encode(), database)
        self.assertNotIn(self.status.encode(), database)
        self.assertNotIn(b"unique credential", database)
        self.assertEqual(self.request("/routeros7.rsc", issued["token"])[0], "401 Unauthorized")
        status, headers, data = self.request("/routeros6.rsc", issued["token"])
        self.assertEqual(status, "200 OK")
        self.assertEqual(data, b"private installer with unique credential")
        self.assertIn("no-store", headers["Cache-Control"])
        self.assertEqual(self.request(token=issued["token"])[0], "401 Unauthorized")
        with self.store.connect() as db:
            self.assertEqual(
                db.execute("SELECT nonce,ciphertext,state FROM deployments").fetchone(), (None, None, "downloaded")
            )

    def test_concurrent_redemption_has_exactly_one_winner(self):
        issued = self.issue()

        def redeem(_):
            try:
                return self.store.redeem(issued["token"])
            except ValueError:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(redeem, range(8)))
        self.assertEqual(sum(value is not None for value in results), 1)

    def test_expired_installer_is_erased_and_revoke_invalidates_status(self):
        import time

        issued = self.issue(now=time.time() - 601)
        self.assertEqual(self.request(token=issued["token"])[0], "401 Unauthorized")
        with self.store.connect() as db:
            self.assertEqual(
                db.execute("SELECT nonce,ciphertext,state FROM deployments").fetchone(), (None, None, "expired")
            )
        self.assertEqual(self.store.authorized_router(self.status), "alice")
        self.store.revoke("alice")
        with self.assertRaises(ValueError):
            self.store.authorized_router(self.status)

    def test_ciphertext_tampering_fails_without_secret_output(self):
        issued = self.issue()
        with self.store.connect() as db:
            db.execute("UPDATE deployments SET ciphertext=?", (b"damaged",))
        status, _, body = self.request(token=issued["token"])
        self.assertEqual(status, "503 Service Unavailable")
        self.assertNotIn(b"unique credential", body)

    def test_receipts_are_router_scoped_and_tokens_cannot_cross_roles(self):
        issued = self.issue()
        self.store.create("bob", 7, b"other", secrets.token_urlsafe(32))
        index = self.root / "receipts"
        index.mkdir()
        (index / "alice.json").write_text(
            json.dumps(dict(version=1, router="alice", receipts={"one.rsc": dict(size=20)}))
        )
        (index / "bob.json").write_text(json.dumps(dict(version=1, router="bob", receipts={"bob.rsc": dict(size=99)})))
        with mock.patch.dict(os.environ, RECEIPT_INDEX=str(index)):
            self.assertEqual(self.request("/v1/receipts/one.rsc", self.status)[2], b"ARCHIVED one.rsc 20\n")
            self.assertEqual(self.request("/v1/receipts/bob.rsc", self.status)[0], "202 Accepted")
            self.assertEqual(self.request("/v1/receipts/one.rsc", issued["token"])[0], "401 Unauthorized")
            self.assertEqual(self.request(token=self.status)[0], "401 Unauthorized")
            self.assertEqual(self.request("/v1/receipts/../bob.json", self.status)[0], "400 Bad Request")
        self.assertEqual(self.request(token=issued["token"], method="HEAD")[0], "405 Method Not Allowed")
        self.assertEqual(self.request(token=issued["token"], query="token=bad")[0], "400 Bad Request")
        self.assertEqual(self.request(token=issued["token"])[0], "200 OK")


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.upload = self.root / "incoming/alice/upload"
        self.upload.mkdir(parents=True)
        self.archive = self.root / "archive"
        self.archive.mkdir()
        self.router = dict(name="alice", uid=10000, enabled=True, max_bytes=100, expected_interval_seconds=86400)
        self.collector = collector.Collector([self.router], self.root / "incoming", self.archive, self.root / "status")
        self.destination = self.archive / "sftp/alice"
        self.receipts = self.destination / ".receipts"
        self.logs = io.StringIO()
        self.capture = mock.patch("sys.stdout", self.logs)
        self.capture.start()
        self.addCleanup(self.capture.stop)

    def put(self, name, when):
        (self.upload / name).write_bytes(b"export")
        (self.upload / (name + ".done.json")).write_text(json.dumps(dict(version=1, filename=name, size=6)))
        with mock.patch.object(collector, "stamp", return_value=when):
            self.collector.cycle()

    def maintain(self, enabled=False):
        parent = os.open(self.archive / "sftp", collector.DIR_FLAGS)
        try:
            with collector.subdir(parent, "alice") as directory:
                with collector.subdir(directory, ".receipts") as receipts:
                    return retention.maintain(
                        directory, receipts, "alice", enabled=enabled, now=datetime(2026, 3, 15, tzinfo=timezone.utc)
                    )
        finally:
            os.close(parent)

    def test_union_of_seven_recent_and_first_success_in_last_twelve_calendar_months(self):
        for name, date in (
            ("old.rsc", "2025-03-01"),
            ("apr-first.rsc", "2025-04-03"),
            ("apr-second.rsc", "2025-04-10"),
            ("jan-first.rsc", "2026-01-04"),
            ("jan-second.rsc", "2026-01-05"),
        ):
            self.put(name, date + "T03:00:00+00:00")
        for day in range(1, 10):
            self.put(f"mar-{day}.rsc", f"2026-03-{day:02d}T03:00:00+00:00")
        legacy = self.archive / "legacy.backup"
        legacy.write_bytes(b"preserve legacy")
        preview = self.maintain()
        self.assertEqual(set(preview["prune"]), {"old.rsc", "apr-second.rsc", "jan-second.rsc", "mar-2.rsc"})
        self.assertTrue((self.destination / "old.rsc").exists())
        self.maintain(enabled=True)
        self.assertEqual(legacy.read_bytes(), b"preserve legacy")
        self.assertTrue((self.destination / "apr-first.rsc").exists())
        self.assertFalse((self.destination / "apr-second.rsc").exists())
        self.assertEqual(self.maintain()["prune"], [])

    def test_duplicate_delivery_keeps_original_receipt_date(self):
        self.put("first.rsc", "2025-04-03T00:00:00+00:00")
        self.put("first.rsc", "2026-03-01T00:00:00+00:00")
        receipt = json.loads((self.receipts / "first.rsc.json").read_text())
        self.assertEqual(receipt["archived_at"], "2025-04-03T00:00:00+00:00")

    def test_selection_leap_day_year_boundary_missing_months_and_small_sets(self):
        records = [
            dict(filename=name, _when=datetime.fromisoformat(date).replace(tzinfo=timezone.utc))
            for name, date in (("leap", "2024-02-29"), ("dec", "2024-12-31"), ("jan", "2025-01-02"))
        ]
        self.assertEqual(
            retention.selection(records, datetime(2025, 1, 5, tzinfo=timezone.utc)), {"leap", "dec", "jan"}
        )
        self.assertEqual(retention.selection([], datetime(2025, 1, 5, tzinfo=timezone.utc)), set())
        records += [
            dict(filename=f"recent-{day}", _when=datetime(2025, 1, day, tzinfo=timezone.utc)) for day in range(10, 17)
        ]
        records.append(dict(filename="outside-window", _when=datetime(2024, 1, 1, tzinfo=timezone.utc)))
        keep = retention.selection(records, datetime(2025, 1, 31, tzinfo=timezone.utc))
        self.assertIn("leap", keep)
        self.assertIn("dec", keep)
        self.assertNotIn("outside-window", keep)

    def test_rejected_upload_and_idle_cycle_cannot_initiate_pruning(self):
        for day in range(1, 10):
            self.put(f"day-{day}.rsc", f"2026-03-{day:02d}T03:00:00+00:00")
        (self.upload / "unsafe.rsc.done.json").write_text('{"invalid":true}')
        self.collector.retention_enabled = True
        self.collector.cycle()
        self.assertTrue((self.destination / "day-2.rsc").exists())

    def test_pruning_restart_recovers_payload_deleted_before_receipt(self):
        for day in range(1, 10):
            self.put(f"day-{day}.rsc", f"2026-03-{day:02d}T03:00:00+00:00")
        original = os.unlink

        def fail_receipt(path, *args, **kwargs):
            if path == "day-2.rsc.json":
                raise OSError("simulated interrupted prune")
            return original(path, *args, **kwargs)

        with mock.patch.object(retention.os, "unlink", side_effect=fail_receipt):
            with self.assertRaises(OSError):
                self.maintain(enabled=True)
        self.assertFalse((self.destination / "day-2.rsc").exists())
        self.assertTrue((self.receipts / "day-2.rsc.json").exists())
        with mock.patch.object(
            retention, "finish_prunes", side_effect=AssertionError("preview must never recover/delete")
        ):
            retention.preview(self.archive, [self.router])
        self.assertTrue((self.receipts / "day-2.rsc.json").exists())
        self.maintain(enabled=True)
        self.assertFalse((self.receipts / "day-2.rsc.json").exists())
        self.assertFalse(list(self.destination.glob(".prune-*")))


class RenderingTests(unittest.TestCase):
    def test_revocation_cannot_claim_success_when_control_service_is_unavailable(self):
        spec = importlib.util.spec_from_file_location("manage", ROOT / "scripts/manage.py")
        manage = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(manage)
        from argparse import Namespace

        with (
            mock.patch.object(manage, "control", side_effect=ValueError("offline")),
            mock.patch.object(manage, "apply_registry") as apply,
        ):
            with self.assertRaises(ValueError):
                manage.deployment(Namespace(deployment_command="revoke", name="alice"), Path("unused"))
            apply.assert_not_called()

    def test_v6_complete_job_redacts_exports_and_never_deletes_pending_exports(self):
        router = dict(name="alice", max_bytes=100000)
        installer = routeros.render(
            router, 6, "203.0.113.1", 15101, "https://mkbackup.example.com", "admin", "s" * 43, password="p" * 43
        ).decode()
        self.assertNotRegex(installer, r"@[A-Z_]+@")
        self.assertIn("hide-sensitive", installer)
        self.assertIn("mode=ftp", installer)
        self.assertIn("port=15101", installer)
        self.assertNotIn("sftp-known-hosts", installer)
        self.assertIn("check-certificate=yes", installer)
        self.assertIn("disabled=yes", installer)
        self.assertIn("initial export and archival confirmation", installer)
        self.assertIn("|generating", installer)
        self.assertIn("|pending", installer)
        self.assertIn("|confirmed", installer)
        self.assertIn("mkbackup-install.rsc", installer)
        self.assertNotIn("/system backup", installer)
        import re

        quoted_job = re.search(r'source="((?:\\.|[^"\\])*)" comment=\$managed', installer).group(1)
        job = json.loads('"' + quoted_job.replace("\\$", "$") + '"')
        self.assertNotIn("p" * 43, job)
        self.assertNotIn("s" * 43, job)
        self.assertIn("mkbackup-credentials.txt", job)

    def test_cli_text_cannot_be_injected_into_script(self):
        router = dict(name="alice", max_bytes=1000)
        for url, owner, host in (
            ("http://example.com", "admin", "203.0.113.1"),
            ("https://example.com/evil", "admin", "203.0.113.1"),
            ("https://example.com", 'admin";:error', "203.0.113.1"),
            ("https://example.com", "admin", "1.2.3.4;:error"),
        ):
            with self.assertRaises(ValueError):
                routeros.render(router, 6, host, 15101, url, owner, "s" * 43, password="p" * 43)

    def test_v1_sftp_compatibility_and_v2_ftp_identity_validation(self):
        config = dict(version=2, routers=[dict(name="alice", uid=10000, transport="ftp", keys=[])])
        self.assertEqual(parse_routers(json.dumps(config))[0]["transport"], "ftp")
        config["routers"][0]["transport"] = "unknown"
        with self.assertRaises(ValueError):
            parse_routers(json.dumps(config))
