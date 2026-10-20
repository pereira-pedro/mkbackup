import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "publication", Path(__file__).resolve().parents[1] / "scripts/publication.py"
)
publication = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publication)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for name in publication.ROOT_FILES:
            (self.root / name).write_text("public source\n")
        (self.root / "scripts").mkdir()
        (self.root / "scripts/example.py").write_text("print('public')\n")

    def test_export_excludes_credentials_history_and_payloads_and_records_hashes(self):
        for name in (".env", "virtusers.txt", "router.backup"):
            (self.root / name).write_text("private\n")
        (self.root / "secrets").mkdir()
        (self.root / "secrets/router.pem").write_text("private\n")
        destination = self.root / "dist/release"
        count = publication.export(destination, self.root)
        with zipfile.ZipFile(destination.with_suffix(".zip")) as archive:
            names = archive.namelist()
        self.assertEqual(count, len(names))
        self.assertFalse(any(name.endswith(("/.env", "/virtusers.txt", ".pem", ".backup")) for name in names))
        self.assertFalse((destination / "secrets").exists())
        self.assertFalse((destination / ".git").exists())
        manifest = json.loads(destination.with_suffix(".manifest.json").read_text())
        import hashlib

        for name, checksum in manifest.items():
            self.assertEqual(checksum, hashlib.sha256((destination / name).read_bytes()).hexdigest())
        with self.assertRaisesRegex(ValueError, "already exists"):
            publication.export(destination, self.root)

    def test_symlinked_source_and_private_keys_stop_export(self):
        path = self.root / "scripts/example.py"
        path.unlink()
        path.symlink_to(self.root / ".env.example")
        with self.assertRaisesRegex(ValueError, "symlinked"):
            publication.check(self.root)
        path.unlink()
        path.write_text("-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 64 + "\n")
        with self.assertRaisesRegex(ValueError, "Private key material"):
            publication.check(self.root)

    def test_documentation_cannot_link_private_unpublished_or_missing_files(self):
        for target in ("secrets/router.pem", "missing.md", "../outside.md"):
            (self.root / "README.md").write_text("[link](" + target + ")\n")
            with self.subTest(target=target), self.assertRaises(ValueError):
                publication.check(self.root)

    def test_populated_router_inventory_cannot_be_published(self):
        (self.root / "docs").mkdir()
        inventory = self.root / "docs/router-inventory.csv"
        inventory.write_text("router_id,model\nprivate-router,private-model\n")
        with self.assertRaisesRegex(ValueError, "never router data"):
            publication.export(self.root / "dist/release", self.root)
        self.assertFalse((self.root / "dist").exists())
