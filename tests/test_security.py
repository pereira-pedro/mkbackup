import contextlib
import errno
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "container"))
import collector
from common import DONE, fingerprint, parse_routers, public_key


class RegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.folder.cleanup)
        key = Path(cls.folder.name) / "router.pem"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "rsa", "-b", "3072", "-m", "PEM", "-N", "", "-f", str(key)], check=True
        )
        cls.key = key.with_suffix(".pem.pub").read_text()

    def config(self, **changes):
        entry = dict(name="alice", uid=10000, keys=[self.key])
        entry.update(changes)
        return json.dumps(dict(version=1, routers=[entry]))

    def test_rsa_registry_defaults_and_fingerprint(self):
        router = parse_routers(self.config())[0]
        self.assertEqual(router["max_bytes"], 100 * 1024 * 1024)
        self.assertEqual(router["uid"], 10000)
        self.assertTrue(fingerprint(self.key).startswith("SHA256:"))
        self.assertEqual(router["keys"], [public_key(self.key)])

    def test_unsafe_names_identity_collisions_and_auth_options_rejected(self):
        for changes in (
            {"name": "../root"},
            {"name": "root"},
            {"name": "alice\nPermitRootLogin yes"},
            {"uid": 0},
            {"uid": True},
            {"max_bytes": True},
            {"keys": []},
            {"keys": ['command="id" ' + self.key]},
            {"keys": [None]},
            {"keys": ["ssh-ed25519 AAAA"]},
            {"keys": ["ssh-rsa invalid"]},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                parse_routers(self.config(**changes))
        entry = json.loads(self.config())["routers"][0]
        for duplicate in (dict(entry, name="bob"), dict(entry, name="bob", uid=10001)):
            with self.assertRaises(ValueError):
                parse_routers(json.dumps(dict(version=1, routers=[entry, duplicate])))
        with self.assertRaises(ValueError):
            parse_routers('{"version":1,"version":1,"routers":[]}')

    def test_enrollment_uid_rotation_bundle_and_staged_revocation(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            key = Path(self.folder.name) / "router.pem.pub"

            def manage(*args):
                return subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "scripts/manage.py"),
                        "--offline",
                        "--secrets-dir",
                        str(folder / "secrets"),
                        *args,
                    ],
                    capture_output=True,
                    text=True,
                    check=True,
                )

            manage("init")
            manage("enroll", "alice", "--public-key", str(key))
            manage("enroll", "alice", "--public-key", str(key))
            registry = folder / "secrets/routers.json"
            accounts = parse_routers(registry.read_text())
            self.assertEqual(accounts[0]["uid"], 10000)
            self.assertEqual(len(accounts[0]["keys"]), 1)
            self.assertEqual(registry.stat().st_mode & 0o777, 0o600)
            manage(
                "bundle", "alice", "--host", "203.0.113.1", "--job-owner", "admin", "--output", str(folder / "bundle")
            )
            script = (folder / "bundle/upload.rsc").read_text()
            self.assertNotIn("@", script)
            self.assertNotIn("password=", script)
            self.assertIn("sftp-known-hosts-ignore=no", script)
            self.assertIn(".done.json", script)
            self.assertNotIn("PRIVATE KEY", (folder / "bundle/enroll.rsc").read_text())
            self.assertIn("host=203.0.113.1 port=15100", (folder / "bundle/enroll.rsc").read_text())
            output = manage("revoke-key", "alice", "--fingerprint", fingerprint(self.key), "--stage-only")
            self.assertIn("STAGED ONLY", output.stdout)
            self.assertFalse(parse_routers(registry.read_text())[0]["enabled"])

    def test_ros6_manual_sftp_bundle_is_rejected(self):
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/manage.py"),
                "bundle",
                "alice",
                "--routeros-major",
                "6",
                "--host",
                "203.0.113.1",
                "--job-owner",
                "admin",
                "--output",
                "/unused",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid choice", result.stderr)

    def test_multiple_env_files_keep_compose_precedence(self):
        spec = importlib.util.spec_from_file_location("manage", ROOT / "scripts/manage.py")
        manage = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(manage)
        with mock.patch.object(
            sys, "argv", ["manage.py", "--env-file", ".env", "--env-file", "secrets/local.env", "init"]
        ):
            with mock.patch.object(manage, "execute"):
                with tempfile.TemporaryDirectory() as folder:
                    sys.argv[1:1] = ["--secrets-dir", folder]
                    manage.main()
        self.assertEqual(
            manage.COMPOSE[-4:],
            ["--env-file", str((ROOT / ".env").resolve()), "--env-file", str((ROOT / "secrets/local.env").resolve())],
        )

    def test_ftp_identity_cannot_generate_an_sftp_bundle(self):
        spec = importlib.util.spec_from_file_location("manage", ROOT / "scripts/manage.py")
        manage = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(manage)
        with self.assertRaisesRegex(ValueError, "SFTP identity"):
            manage.bundle(None, {"transport": "ftp"}, None)

    def test_live_apply_uses_authoritative_registry_and_terminates_sessions(self):
        spec = importlib.util.spec_from_file_location("manage", ROOT / "scripts/manage.py")
        manage = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(manage)
        with (
            mock.patch.object(manage, "control", side_effect=[dict(generation=2), dict(routers=[])]),
            mock.patch.object(manage.subprocess, "run") as run,
        ):
            manage.apply_registry(Path(self.folder.name) / "routers.json")
        self.assertIn("--force-recreate", run.call_args.args[0])
        self.assertEqual(run.call_args.args[0][-2:], ["sftp", "collector"])


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.incoming, self.archive = self.folder / "incoming", self.folder / "archive"
        self.upload = self.incoming / "alice/upload"
        self.upload.mkdir(parents=True)
        self.archive.mkdir()
        self.router = dict(
            name="alice", uid=10000, enabled=True, max_bytes=100, expected_interval_seconds=86400, keys=[]
        )
        self.service = collector.Collector([self.router], self.incoming, self.archive, self.folder / "status.json")
        self.destination = self.archive / "sftp/alice"
        self.log = contextlib.redirect_stdout(io.StringIO())
        self.log.__enter__()
        self.addCleanup(lambda: self.log.__exit__(None, None, None))

    def put(self, name="first.backup", data=b"original backup", manifest=None):
        (self.upload / name).write_bytes(data)
        (self.upload / (name + DONE)).write_text(
            json.dumps(dict(version=1, filename=name, size=len(data)) if manifest is None else manifest)
        )

    def cycle(self):
        return self.service.cycle()

    def test_completed_archive_has_new_inode_receipt_and_persistent_status(self):
        self.put()
        original = (self.upload / "first.backup").stat().st_ino
        state = self.cycle()
        archived = self.destination / "first.backup"
        self.assertEqual(archived.read_bytes(), b"original backup")
        self.assertNotEqual(archived.stat().st_ino, original)
        self.assertEqual(archived.stat().st_mode & 0o777, 0o400)
        self.assertFalse((self.upload / "first.backup").exists())
        receipt = json.loads((self.destination / ".receipts/first.backup.json").read_text())
        self.assertEqual(receipt["size"], 15)
        self.assertEqual(state["routers"]["alice"]["last_success"], receipt)
        restarted = collector.Collector([self.router], self.incoming, self.archive, self.folder / "status.json")
        self.assertEqual(restarted.cycle()["routers"]["alice"]["last_success"], receipt)

    def test_duplicate_is_idempotent_and_conflict_cannot_replace_archive(self):
        self.put()
        self.cycle()
        archive = self.destination / "first.backup"
        inode = archive.stat().st_ino
        self.put()
        self.cycle()
        self.assertEqual(archive.stat().st_ino, inode)
        self.put(data=b"malicious replacement")
        result = self.cycle()
        self.assertEqual(archive.read_bytes(), b"original backup")
        self.assertTrue(result["routers"]["alice"]["last_error"])

    def test_interrupted_upload_has_no_completed_archive(self):
        (self.upload / "pending.backup").write_bytes(b"incomplete")
        self.cycle()
        self.assertFalse((self.destination / "pending.backup").exists())
        self.put(manifest=dict(version=1, filename="first.backup", size=99))
        self.cycle()
        self.assertFalse((self.destination / "first.backup").exists())

    def test_manifest_traversal_duplicate_fields_and_limits_rejected(self):
        for manifest in (
            dict(version=1, filename="../legacy.backup", size=1),
            dict(version=1, filename="first.backup", size=True),
            dict(version=1, filename="first.backup", size=101),
            dict(version=1, filename="first.backup", size=1, router="bob"),
        ):
            self.put(data=b"x", manifest=manifest)
            self.cycle()
            self.assertFalse((self.destination / "first.backup").exists())
        (self.upload / ("first.backup" + DONE)).write_text('{"version":1,"filename":"first.backup","size":1,"size":1}')
        self.cycle()
        self.assertFalse((self.destination / "first.backup").exists())

    def test_symlinks_hardlinks_and_special_files_are_rejected(self):
        self.put()
        source = self.upload / "first.backup"
        outside = self.folder / "outside"
        outside.write_bytes(b"original backup")
        source.unlink()
        source.symlink_to(outside)
        self.cycle()
        self.assertFalse((self.destination / "first.backup").exists())
        source.unlink()
        os.link(outside, source)
        self.cycle()
        self.assertFalse((self.destination / "first.backup").exists())
        source.unlink()
        os.mkfifo(source)
        self.cycle()
        self.assertFalse((self.destination / "first.backup").exists())

    def test_payload_changed_while_copying_is_not_published(self):
        self.put()
        original = collector.write_all

        def mutate(fd, content):
            original(fd, content)
            (self.upload / "first.backup").write_bytes(b"changed content")

        with mock.patch.object(collector, "write_all", side_effect=mutate):
            self.cycle()
        self.assertFalse((self.destination / "first.backup").exists())

    def test_disk_full_never_completes_an_archive(self):
        self.put()
        with mock.patch.object(collector, "write_all", side_effect=OSError(errno.ENOSPC, "simulated full disk")):
            state = self.cycle()
        self.assertFalse(state["healthy"])
        self.assertFalse((self.destination / "first.backup").exists())
        self.assertFalse(list(self.destination.glob(".tmp-*")))
        self.assertIsNone(state["routers"]["alice"]["last_success"])

    def test_restart_recovers_publication_before_receipt_without_replacing_inode(self):
        self.put()
        with mock.patch.object(collector, "exclusive_json", side_effect=OSError(errno.EIO, "simulated crash")):
            self.cycle()
        archive = self.destination / "first.backup"
        inode = archive.stat().st_ino
        self.assertFalse((self.destination / ".receipts/first.backup.json").exists())
        self.cycle()
        self.assertEqual(archive.stat().st_ino, inode)
        self.assertTrue((self.destination / ".receipts/first.backup.json").is_file())

    def test_restart_removes_only_internal_stages_and_preserves_published_inode(self):
        self.put()
        self.cycle()
        archive = self.destination / "first.backup"
        inode = archive.stat().st_ino
        leftover = self.destination / (".tmp-" + "a" * 32)
        os.link(archive, leftover)
        unrelated = self.destination / ".tmp-admin-notes"
        unrelated.write_text("keep")
        restarted = collector.Collector([self.router], self.incoming, self.archive, self.folder / "status.json")
        state = restarted.cycle()
        self.assertFalse(leftover.exists())
        self.assertEqual(archive.stat().st_ino, inode)
        self.assertTrue(unrelated.exists())
        self.assertIn("available_bytes", state["storage"]["incoming"])

    def test_legacy_data_is_not_changed_and_disabled_router_is_not_collected(self):
        legacy = self.archive / "legacy.backup"
        legacy.write_bytes(b"legacy")
        legacy.chmod(0o640)
        self.router["enabled"] = False
        self.put()
        self.cycle()
        self.assertEqual(legacy.read_bytes(), b"legacy")
        self.assertEqual(legacy.stat().st_mode & 0o777, 0o640)
        self.assertFalse((self.destination / "first.backup").exists())


if __name__ == "__main__":
    unittest.main()
