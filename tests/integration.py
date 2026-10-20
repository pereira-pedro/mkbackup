"""Build mkbackup-sftp-test:local first; test only temporary Compose resources."""

import ftplib
import hashlib
import http.cookiejar
import io
import json
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from sftp_client import SFTP, SFTPError, string, u32

ROOT = Path(__file__).resolve().parents[1]


class IntegrationTests(unittest.TestCase):
    live = False

    @classmethod
    def compose(cls, *args, check=True, input=None):
        result = subprocess.run(
            [
                "docker",
                "compose",
                "--profile",
                "legacy",
                "--profile",
                "deployment",
                "--profile",
                "admin",
                "--env-file",
                str(cls.envfile),
                "-p",
                cls.project,
                "-f",
                str(ROOT / "docker-compose.yml"),
                "-f",
                str(cls.override),
                *args,
            ],
            check=False,
            capture_output=True,
            text=True,
            input=input,
        )
        if check and result.returncode:
            collected = cls.compose("logs", "--no-color", check=False) if args and args[0] == "up" else None
            logs = collected.stdout + collected.stderr if collected else ""
            raise RuntimeError(result.stderr + result.stdout + logs)
        return result

    @classmethod
    def manage(cls, *args):
        options = (
            [
                "--project-name",
                cls.project,
                "--env-file",
                str(cls.envfile),
                "--compose-file",
                str(ROOT / "docker-compose.yml"),
                "--compose-file",
                str(cls.override),
            ]
            if cls.live
            else ["--offline"]
        )
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/manage.py"),
                "--secrets-dir",
                str(cls.folder / "secrets"),
                *options,
                *args,
            ],
            check=True,
            capture_output=True,
        )

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="mkbackup-sftp-test-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.folder = Path(cls.temporary.name)
        cls.project = "mkbackup-sftp-test-" + secrets.token_hex(4)
        cls.manage("init")
        for name in ("alice", "bob", "unknown", "rotated"):
            cls.manage("keygen", name, "--output-dir", str(cls.folder / "clients"))
            if name in ("alice", "bob"):
                cls.manage("enroll", name, "--public-key", str(cls.folder / "clients" / (name + ".pem.pub")))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            cls.port = listener.getsockname()[1]

        def free_port():
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                return listener.getsockname()[1]

        cls.ftp_port, cls.https_port, cls.caddy_port = free_port(), free_port(), free_port()
        cls.passive_min = 31000 + secrets.randbelow(10000)
        cls.password = secrets.token_urlsafe(32)
        cls.admin_password = secrets.token_urlsafe(32)
        hashed = (
            subprocess.check_output(["openssl", "passwd", "-6", "-stdin"], input=cls.password.encode()).decode().strip()
        )
        (cls.folder / "secrets/ftp_passwords.json").write_text(json.dumps(dict(legacy=hashed, legacybob=hashed)))
        registry = cls.folder / "secrets/routers.json"
        data = json.loads(registry.read_text())
        data["version"] = 2
        data["routers"] += [
            dict(name=name, uid=uid, keys=[], transport="ftp")
            for name, uid in (("legacy", 10002), ("legacybob", 10003))
        ]
        registry.write_text(json.dumps(data))
        hostkey = subprocess.check_output(
            ["ssh-keygen", "-y", "-P", "", "-f", str(cls.folder / "secrets/ssh_host_rsa_key")], text=True
        ).strip()
        cls.known_hosts = cls.folder / "known_hosts"
        cls.known_hosts.write_text(f"[127.0.0.1]:{cls.port} {hostkey}\n")
        cls.envfile = cls.folder / ".env"
        cls.envfile.write_text(
            f"SFTP_BIND_ADDRESS=127.0.0.1\nSFTP_PORT={cls.port}\nCOLLECT_INTERVAL_SECONDS=1\n"
            f"ROUTERS_FILE={cls.folder}/secrets/routers.json\n"
            f"SSH_HOST_RSA_KEY_FILE={cls.folder}/secrets/ssh_host_rsa_key\n"
            f"SSH_HOST_RSA_PUBLIC_KEY_FILE={cls.folder}/secrets/ssh_host_rsa_key.pub\n"
            f"SSH_HOST_ED25519_KEY_FILE={cls.folder}/secrets/ssh_host_ed25519_key\n"
            f"FTP_PASSWORDS_FILE={cls.folder}/secrets/ftp_passwords.json\nENROLLMENT_KEY_FILE={cls.folder}/secrets/enrollment.key\n"
            f"FTP_BIND_ADDRESS=127.0.0.1\nFTP_PORT={cls.ftp_port}\nFTP_PUBLIC_ADDRESS=127.0.0.1\n"
            f"FTP_PASSIVE_MIN={cls.passive_min}\nFTP_PASSIVE_MAX={cls.passive_min + 3}\n"
            f"ENROLLMENT_BASE_URL=https://localhost:{cls.https_port}\nDEPLOYMENT_HOST=localhost\nCADDY_BIND_ADDRESS=127.0.0.1\nCADDY_PORT={cls.caddy_port}\n"
            f"ADMIN_PASSWORD={cls.admin_password}\n"
        )
        # Exercise the production Caddyfile over HTTP behind real HAProxy TLS.
        cert, key = cls.folder / "tls.crt", cls.folder / "tls.key"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
            ],
            check=True,
            capture_output=True,
        )
        pem = cls.folder / "tls.pem"
        pem.write_bytes(cert.read_bytes() + key.read_bytes())
        pem.chmod(0o444)  # Disposable fixture readable by the unprivileged proxy.
        haproxy = cls.folder / "haproxy.cfg"
        haproxy.write_text(
            (ROOT / "docs/haproxy.cfg.example")
            .read_text()
            .replace("mkbackup.example.com", "localhost")
            .replace("bind :443", "bind :8443")
            .replace("/etc/haproxy/certs/localhost.pem", "/usr/local/etc/haproxy/tls.pem")
            .replace("server caddy 127.0.0.1:15102 check", "server caddy https:15102 check")
        )
        cls.tls = ssl.create_default_context(cadata=cert.read_text())
        cls.override = cls.folder / "override.json"
        services = {
            name: {"image": "mkbackup-sftp-test:local", "restart": "no"}
            for name in ("sftp", "collector", "ftp", "enrollment", "admin", "archive-reader", "provisioner")
        }
        services["https"] = dict(restart="no")
        services["haproxy"] = dict(
            image="haproxy:3.2-alpine@sha256:254e6370f01cd654e0744edf607c67f33777c1b6a9dc0d4b28bcba7171460122",
            profiles=["deployment"],
            restart="no",
            user="10001:10001",
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            pids_limit=64,
            mem_limit="128m",
            ports=[f"127.0.0.1:{cls.https_port}:8443"],
            volumes=[
                str(haproxy) + ":/usr/local/etc/haproxy/haproxy.cfg:ro",
                str(pem) + ":/usr/local/etc/haproxy/tls.pem:ro",
            ],
            depends_on={"https": dict(condition="service_started")},
        )
        cls.override.write_text(json.dumps(dict(services=services)))
        cls.addClassCleanup(lambda: cls.compose("down", "--volumes", "--remove-orphans", check=False))
        # Seed only this test project's archive volume. It stands in for the
        # previous deployment's data and must survive the migration unchanged.
        cls.compose(
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "python3",
            "collector",
            "-c",
            "from pathlib import Path; p=Path('/archive/legacy.backup'); p.write_bytes(b'legacy'); p.chmod(0o640)",
        )
        cls.compose(
            "up",
            "-d",
            "--no-build",
            "--wait",
            "--wait-timeout",
            "90",
            "sftp",
            "collector",
            "ftp",
            "enrollment",
            "admin",
            "archive-reader",
            "https",
            "haproxy",
        )
        cls.live = True
        cls.wait_ready()
        for _ in range(40):
            try:
                with urllib.request.urlopen(
                    f"https://localhost:{cls.https_port}/healthz", context=cls.tls, timeout=3
                ) as response:
                    if response.read() == b"ok\n":
                        break
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.25)
        else:
            raise RuntimeError(cls.compose("logs", "--no-color").stdout)

    @classmethod
    def wait_ready(cls):
        for _ in range(40):
            try:
                client = SFTP(cls.port, cls.folder / "clients/alice.pem", cls.known_hosts)
                client.close()
                return
            except (SFTPError, OSError):
                time.sleep(0.25)
        raise RuntimeError(cls.compose("logs", "--no-color").stdout)

    def client(self, name="alice", key=None, known_hosts=None, extra=()):
        client = SFTP(
            self.port, key or self.folder / ("clients/" + name + ".pem"), known_hosts or self.known_hosts, name, extra
        )
        self.addCleanup(client.close)
        return client

    def exec_python(self, service, code):
        return self.compose("exec", "-T", service, "python3", "-c", code)

    def archived(self, name, content, router="alice"):
        for _ in range(40):
            result = self.compose(
                "exec",
                "-T",
                "collector",
                "python3",
                "-c",
                f"from pathlib import Path; import hashlib; p=Path('/archive/sftp/{router}/{name}'); "
                f"assert hashlib.sha256(p.read_bytes()).hexdigest() == '{hashlib.sha256(content).hexdigest()}'; "
                f"assert p.stat().st_mode & 0o777 == 0o400; assert p.stat().st_uid == 0; "
                f"assert (p.parent/'.receipts'/'{name}.json').is_file()",
                check=False,
            )
            if result.returncode == 0:
                return
            time.sleep(0.1)
        self.fail("No completed archive: " + self.compose("logs", "--no-color").stdout)

    def test_01_key_authentication_and_weak_auth_rejected(self):
        client = self.client()
        client.put("/upload/no-marker.backup", b"pending only")
        for extra, key, user in (
            ((), self.folder / "clients/unknown.pem", "alice"),
            (("-o", "PubkeyAcceptedAlgorithms=ssh-rsa"), self.folder / "clients/alice.pem", "alice"),
            (("-o", "PreferredAuthentications=password"), self.folder / "clients/alice.pem", "alice"),
            ((), self.folder / "clients/alice.pem", "root"),
        ):
            with self.subTest(extra=extra, user=user), self.assertRaises(SFTPError):
                SFTP(self.port, key, self.known_hosts, user, extra)

    def test_02_sftp_restrictions_and_user_isolation(self):
        client = self.client()
        client.put("/upload/private.backup", b"pending")
        handle = client.open("/upload/private.backup", 1)
        for kind, payload in (
            (5, string(handle) + b"\0" * 8 + u32(32)),
            (13, string("/upload/private.backup")),
            (18, string("/upload/private.backup") + string("/upload/renamed.backup")),
            (14, string("/upload/subdirectory") + u32(0)),
            (15, string("/upload")),
            (20, string("/upload/link") + string("/etc/passwd")),
            (200, string("hardlink@openssh.com") + string("/upload/private.backup") + string("/upload/hardlink")),
            (3, string("/../../etc/passwd") + u32(1) + u32(0)),
            (3, string("/bob/upload/steal") + u32(26) + u32(0)),
        ):
            with self.subTest(kind=kind), self.assertRaises(SFTPError):
                client.request(kind, payload)
        client.close_handle(handle)
        self.client("bob").put("/upload/bob.backup", b"bob")

    def test_03_separate_archive_inode_with_held_open_write_handle(self):
        client = self.client()
        name, content = "held-open.backup", b"a retained router backup"
        handle = client.open("/upload/" + name)
        client.write(handle, content)
        client.put(
            "/upload/" + name + ".done.json", json.dumps(dict(version=1, filename=name, size=len(content))).encode()
        )
        self.archived(name, content)
        client.write(handle, b"MALICIOUS", 0)
        client.close_handle(handle)
        self.archived(name, content)
        # A new upload with the same name must never replace the archive.
        client.put("/upload/" + name, b"different")
        client.put("/upload/" + name + ".done.json", json.dumps(dict(version=1, filename=name, size=9)).encode())
        time.sleep(1.2)
        self.archived(name, content)

    def test_04_host_key_pinning_and_container_hardening(self):
        wrong = self.folder / "wrong_hosts"
        wrong.write_text(f"[127.0.0.1]:{self.port} " + (self.folder / "clients/unknown.pem.pub").read_text())
        with self.assertRaises(SFTPError):
            SFTP(self.port, self.folder / "clients/alice.pem", wrong)
        for service in ("sftp", "collector"):
            container = self.compose("ps", "-q", service).stdout.strip()
            info = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
            self.assertTrue(info["HostConfig"]["ReadonlyRootfs"])
            self.assertEqual(info["HostConfig"]["CapDrop"], ["ALL"])
            self.assertIn("no-new-privileges:true", info["HostConfig"]["SecurityOpt"])
            if service == "sftp":
                self.assertNotIn("/archive", [mount["Destination"] for mount in info["Mounts"]])
            else:
                self.assertEqual(info["HostConfig"]["NetworkMode"], "none")
                self.assertFalse(info["HostConfig"].get("PortBindings"))
        self.exec_python(
            "collector",
            "from pathlib import Path; p=Path('/archive/legacy.backup'); assert p.read_bytes()==b'legacy'; assert p.stat().st_mode & 0o777 == 0o640",
        )
        self.exec_python("sftp", "from pathlib import Path; assert not list(Path('/etc/ssh').glob('ssh_host_*_key'))")

    def test_05_shell_pty_and_forwarding_denied(self):
        base = [
            "ssh",
            "-p",
            str(self.port),
            "-i",
            str(self.folder / "clients/alice.pem"),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=" + str(self.known_hosts),
        ]
        for extra in (
            ("alice@127.0.0.1", "id"),
            ("-tt", "alice@127.0.0.1", "id"),
            ("-o", "ExitOnForwardFailure=yes", "-N", "-R", "0:127.0.0.1:22", "alice@127.0.0.1"),
        ):
            result = subprocess.run(base + list(extra), input=b"", capture_output=True, timeout=8)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b"uid=", result.stdout)

    def test_06_restart_rotation_and_revocation_terminate_sessions(self):
        # Overlap a second key first, then apply the registry as the operator would.
        self.manage("enroll", "alice", "--public-key", str(self.folder / "clients/rotated.pem.pub"))
        self.manage("apply")
        self.wait_ready()
        old = self.client()
        self.client(key=self.folder / "clients/rotated.pem").close()
        before = old.open("/upload/session.backup")
        self.exec_python(
            "collector",
            "from pathlib import Path; assert Path('/archive/sftp/alice/held-open.backup').read_bytes() == b'a retained router backup'",
        )
        # Stage the helper's revocation then apply to THIS disposable project only.
        key = (self.folder / "clients/alice.pem.pub").read_text().split()[1]
        import base64

        fp = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(key)).digest()).decode().rstrip("=")
        self.manage("revoke-key", "alice", "--fingerprint", fp, "--stage-only")
        self.manage("apply")
        for _ in range(30):
            try:
                client = SFTP(self.port, self.folder / "clients/rotated.pem", self.known_hosts)
                client.close()
                break
            except SFTPError:
                time.sleep(0.2)
        else:
            self.fail(self.compose("logs", "--no-color").stdout)
        with self.assertRaises((SFTPError, OSError)):
            old.write(before, b"old session must be dead")
        with self.assertRaises(SFTPError):
            SFTP(self.port, self.folder / "clients/alice.pem", self.known_hosts)
        # Same pinned host key after both recreations, and durable last-success state.
        self.exec_python(
            "collector",
            "import json; from pathlib import Path; s=json.loads(Path('/run/mkbackup/collector-status.json').read_text()); assert s['routers']['alice']['last_success']",
        )

    def ftp(self, user="legacy", password=None):
        client = ftplib.FTP()

        def close():
            try:
                client.quit()
            except (ftplib.Error, OSError, EOFError):
                client.close()

        try:
            client.connect("127.0.0.1", self.ftp_port, timeout=5)
            client.login(user, self.password if password is None else password)
        except BaseException:
            client.close()
            raise
        self.addCleanup(close)
        return client

    def test_07_ftp_credentials_isolation_and_destructive_commands_denied(self):
        with self.assertRaises(ftplib.error_perm) as bad_password:
            self.ftp(password="invalid")
        self.assertTrue(
            str(bad_password.exception).startswith("530"),
            "Bad passwords must fail authentication, not crash the sandbox",
        )
        with self.assertRaises(ftplib.error_perm):
            self.ftp(user="alice")  # SFTP identities cannot log in over FTP.
        client = self.ftp()
        self.exec_python(
            "ftp",
            """from pathlib import Path
import platform
found=False
for proc in Path('/proc').iterdir():
 if not proc.name.isdigit(): continue
 try:
  status=dict(line.split(':',1) for line in (proc/'status').read_text().splitlines() if ':' in line)
  if status.get('Name','').strip()=='vsftpd' and status.get('Uid','').split()[0]=='10002':
   found=True
   assert status['Seccomp'].strip()=='2'
   if platform.machine()=='x86_64': assert int(status['Seccomp_filters'])>=2
 except FileNotFoundError:
  pass
assert found, 'No authenticated FTP worker found'
""",
        )
        client.storbinary("STOR /upload/pending.rsc", io.BytesIO(b"private"))
        for command in (
            "PORT 127,0,0,1,7,138",
            "EPRT |1|127.0.0.1|1930|",
            "RETR /upload/pending.rsc",
            "DELE /upload/pending.rsc",
            "RNFR /upload/pending.rsc",
            "MKD /upload/new",
            "RMD /upload",
            "SITE CHMOD 777 /upload/pending.rsc",
            "CWD /../legacybob/upload",
        ):
            with self.subTest(command=command), self.assertRaises(ftplib.error_perm):
                client.sendcmd(command)
        with self.assertRaises(ftplib.error_perm):
            client.storbinary("STOR /upload/../../legacybob/upload/cross.rsc", io.BytesIO(b"cross-router"))
        self.exec_python(
            "ftp", "from pathlib import Path; assert not Path('/srv/sftp/legacybob/upload/cross.rsc').exists()"
        )
        self.ftp("legacybob").storbinary("STOR /upload/bob.rsc", io.BytesIO(b"bob"))

    def test_08_ftp_open_data_handle_cannot_change_archive(self):
        client = self.ftp()
        content, name = b"a retained FTP export", "held-ftp.rsc"
        client.voidcmd("TYPE I")
        data = client.transfercmd("STOR /upload/" + name)
        self.addCleanup(data.close)
        data.sendall(content)
        marker = json.dumps(dict(version=1, filename=name, size=len(content))).encode()
        other = self.ftp()
        other.storbinary("STOR /upload/" + name + ".done.json", io.BytesIO(marker))
        self.archived(name, content, router="legacy")
        data.sendall(b"MALICIOUS")
        data.close()
        client.voidresp()
        self.archived(name, content, router="legacy")

    def issue(self, name, major):
        result = self.deployment_cli(
            "issue",
            name,
            "--routeros-major",
            str(major),
            "--host",
            "127.0.0.1",
            "--port",
            str(self.ftp_port if major == 6 else self.port),
            "--base-url",
            f"https://localhost:{self.https_port}",
            "--job-owner",
            "admin",
        )
        return re.search(r"Bearer ([A-Za-z0-9_-]{43})", result.stdout).group(1)

    def deployment_cli(self, *args):
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/manage.py"),
                "--secrets-dir",
                str(self.folder / "secrets"),
                "--project-name",
                self.project,
                "--env-file",
                str(self.envfile),
                "--compose-file",
                str(ROOT / "docker-compose.yml"),
                "--compose-file",
                str(self.override),
                "deployment",
                *args,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            # Do not include stdout, which can contain private enrollment tokens.
            raise RuntimeError(result.stderr)
        return result

    def fetch(self, path, token=None, context=None):
        request = urllib.request.Request(
            f"https://localhost:{self.https_port}" + path, headers={"Authorization": "Bearer " + token} if token else {}
        )
        return urllib.request.urlopen(request, context=context or self.tls, timeout=5)

    def test_09_https_enrollment_ftp_and_receipt_confirmation(self):
        token = self.issue("edge6", 6)
        with self.assertRaises(urllib.error.URLError):
            self.fetch("/", token, ssl.create_default_context())
        with self.fetch("/routeros6.rsc", token) as response:
            script = response.read().decode()
            self.assertIn("no-store", response.headers["Cache-Control"])
            self.assertIn(f"https://localhost:{self.https_port}", script)
        with self.assertRaises(urllib.error.HTTPError) as replay:
            self.fetch("/", token)
        self.assertEqual(replay.exception.code, 401)
        # Credentials are RouterOS-escaped inside the installed job source.
        credentials = re.search(r'contents="([A-Za-z0-9_-]{43})\\n([A-Za-z0-9_-]{43})\\n"', script)
        password, status_token = credentials.group(1), credentials.group(2)
        name, content = "edge6-1.rsc", b"/system identity set name=restorable\n"
        client = self.ftp("edge6", password)
        client.storbinary("STOR /upload/" + name, io.BytesIO(content))
        client.storbinary(
            "STOR /upload/" + name + ".done.json",
            io.BytesIO(json.dumps(dict(version=1, filename=name, size=len(content))).encode()),
        )
        self.archived(name, content, "edge6")
        for _ in range(30):
            with self.fetch("/v1/receipts/" + name, status_token) as response:
                body = response.read()
            if body == f"ARCHIVED {name} {len(content)}\n".encode():
                break
            time.sleep(0.2)
        else:
            self.fail("No HTTPS archival confirmation")
        logs = self.compose("logs", "--no-color").stdout
        for secret in (token, password, status_token):
            self.assertNotIn(secret, logs)

    def test_09b_caddy_http_backend_without_tls_redirects_or_storage(self):
        # Browsers and reverse proxies can legitimately add more than 20 fields.
        # Exercise both Gunicorn services through Caddy and real HAProxy TLS,
        # while ensuring that header count and individual size remain bounded.
        for base, context in (
            (f"http://localhost:{self.caddy_port}", None),
            (f"https://localhost:{self.https_port}", self.tls),
        ):
            for path, expected in (("/admin/login", b"Admin password"), ("/healthz", b"ok\n")):
                with self.subTest(base=base, path=path):
                    headers = {f"X-Browser-Header-{index}": "ok" for index in range(40)}
                    request = urllib.request.Request(base + path, headers=headers)
                    with urllib.request.urlopen(request, context=context, timeout=5) as response:
                        self.assertEqual(response.status, 200)
                        self.assertIn(expected, response.read())
                    for excessive in (
                        {f"X-Excess-{index}": "ok" for index in range(110)},
                        {"X-Excess-Size": "x" * 2100},
                    ):
                        request = urllib.request.Request(base + path, headers=excessive)
                        with self.assertRaises(urllib.error.HTTPError) as rejected:
                            urllib.request.urlopen(request, context=context, timeout=5)
                        self.assertEqual(rejected.exception.code, 400)
        request = urllib.request.Request(f"http://127.0.0.1:{self.caddy_port}/healthz", headers={"Host": "localhost"})
        with urllib.request.urlopen(request, timeout=5) as response:
            self.assertEqual(response.read(), b"ok\n")
            self.assertEqual(response.geturl(), request.full_url)
        for host in ("localhost", "127.0.0.1"):
            local_root = urllib.request.Request(f"http://127.0.0.1:{self.caddy_port}/", headers={"Host": host})
            with urllib.request.urlopen(local_root, timeout=5) as response:
                self.assertTrue(response.geturl().endswith("/admin/login"))
                self.assertIn(b"Admin password", response.read())
        invalid_host = urllib.request.Request(
            f"http://127.0.0.1:{self.caddy_port}/", headers={"Host": "unknown.invalid"}
        )
        with self.assertRaises(urllib.error.HTTPError) as rejected:
            urllib.request.urlopen(invalid_host, timeout=5)
        self.assertEqual(rejected.exception.code, 421)
        installer = urllib.request.Request(
            f"http://127.0.0.1:{self.caddy_port}/", headers={"Host": "localhost", "Authorization": "Bearer " + "x" * 43}
        )
        with self.assertRaises(urllib.error.HTTPError) as unauthorized:
            urllib.request.urlopen(installer, timeout=5)
        self.assertEqual(unauthorized.exception.code, 401)
        self.assertEqual(unauthorized.exception.geturl(), installer.full_url)
        container = self.compose("ps", "-q", "https").stdout.strip()
        info = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
        self.assertEqual(set(info["HostConfig"]["PortBindings"]), {"15102/tcp"})
        self.assertEqual([cap.removeprefix("CAP_") for cap in info["HostConfig"]["CapAdd"]], ["NET_BIND_SERVICE"])
        self.assertEqual(info["Config"]["User"], "10001:10001")
        self.assertTrue(info["HostConfig"]["ReadonlyRootfs"])
        self.assertFalse([m for m in info["Mounts"] if m["Type"] == "volume"])

    def test_10_https_enrollment_sftp_and_web_privilege_boundaries(self):
        token = self.issue("edge7", 7)
        with self.fetch("/routeros7.rsc", token) as response:
            script = response.read().decode()
        private = re.search(r'contents="(-----BEGIN RSA PRIVATE KEY-----.*?)"', script).group(1)
        path = self.folder / "edge7.pem"
        path.write_text(json.loads('"' + private + '"'))
        path.chmod(0o600)
        client = SFTP(self.port, path, self.known_hosts, "edge7")
        self.addCleanup(client.close)
        client.put("/upload/key-proven.rsc", b"export")
        self.assertIn("sftp-known-hosts-ignore=no", script)
        container = self.compose("ps", "-q", "enrollment").stdout.strip()
        info = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
        targets = {mount["Destination"] for mount in info["Mounts"]}
        self.assertFalse(
            targets & {"/archive", "/incoming", "/srv/sftp", "/run/secrets/routers", "/var/run/docker.sock"}
        )
        self.exec_python(
            "enrollment",
            "from pathlib import Path; p=[d for d in Path('/proc').iterdir() if d.name.isdigit() and (d/'cmdline').read_bytes().split(bytes([0]))[1:2]==[b'/usr/bin/gunicorn']]; assert p; assert all('Uid:\\t10001' in (d/'status').read_text() for d in p)",
        )

    def test_11_retention_runs_after_upload_and_preserves_first_monthly_copy(self):
        value = json.loads(self.override.read_text())
        value["services"]["collector"]["environment"] = dict(RETENTION_ENABLED="1")
        self.override.write_text(json.dumps(value))
        self.compose("up", "-d", "--no-build", "--force-recreate", "collector")
        client = self.ftp()
        for number in range(1, 10):
            name, content = f"retention-{number}.rsc", f"export {number}".encode()
            client.storbinary("STOR /upload/" + name, io.BytesIO(content))
            client.storbinary(
                "STOR /upload/" + name + ".done.json",
                io.BytesIO(json.dumps(dict(version=1, filename=name, size=len(content))).encode()),
            )
            self.archived(name, content, "legacy")
        self.exec_python(
            "collector",
            "from pathlib import Path; p=Path('/archive/sftp/legacy'); assert (p/'held-ftp.rsc').exists(); assert not (p/'retention-1.rsc').exists(); assert not (p/'retention-2.rsc').exists(); assert (p/'retention-3.rsc').exists(); assert len(list(p.glob('*.rsc')))==8; assert Path('/archive/legacy.backup').read_bytes()==b'legacy'",
        )

    def test_12_deployment_revocation_disables_tokens_and_live_ftp_sessions(self):
        token = self.issue("revokeme", 6)
        with self.fetch("/", token) as response:
            script = response.read().decode()
        credentials = re.search(r'contents="([A-Za-z0-9_-]{43})\\n([A-Za-z0-9_-]{43})\\n"', script)
        password, status_token = credentials.group(1), credentials.group(2)
        client = self.ftp("revokeme", password)
        name, content = "revokeme-20261020000000.rsc", b"retained after revocation\n"
        client.storbinary("STOR /upload/" + name, io.BytesIO(content))
        client.storbinary(
            "STOR /upload/" + name + ".done.json",
            io.BytesIO(json.dumps(dict(version=1, filename=name, size=len(content))).encode()),
        )
        self.archived(name, content, "revokeme")
        self.deployment_cli("revoke", "revokeme")
        with self.assertRaises((ftplib.Error, OSError, EOFError)):
            client.voidcmd("NOOP")
        with self.assertRaises(ftplib.error_perm):
            self.ftp("revokeme", password)
        with self.assertRaises(urllib.error.HTTPError) as revoked:
            self.fetch("/v1/receipts/test.rsc", status_token)
        self.assertEqual(revoked.exception.code, 401)

    def browser(self):
        jar = http.cookiejar.CookieJar()
        browser = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self.tls), urllib.request.HTTPCookieProcessor(jar)
        )
        return browser, jar

    def admin_request(self, browser, path, data=None, headers=None):
        import urllib.parse

        request = urllib.request.Request(
            f"https://localhost:{self.https_port}" + path,
            data=urllib.parse.urlencode(data).encode() if data is not None else None,
            headers=headers or {},
        )
        return browser.open(request, timeout=15)

    def admin_login(self):
        browser, jar = self.browser()
        with self.admin_request(browser, "/admin/login") as response:
            html = response.read().decode()
            self.assertIn("Secure", response.headers["Set-Cookie"])
            self.assertIn("HttpOnly", response.headers["Set-Cookie"])
            self.assertIn("SameSite=Strict", response.headers["Set-Cookie"])
        csrf = re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"', html).group(1)
        before = list(jar)[0].value
        with self.admin_request(browser, "/admin/login", dict(csrf=csrf, password=self.admin_password)) as response:
            self.assertIn(b"Routers", response.read())
        self.assertNotEqual(before, list(jar)[0].value)
        return browser, jar

    def test_13_admin_login_search_download_logout_and_isolation(self):
        browser, jar = self.admin_login()
        with self.admin_request(browser, "/admin/?q=EDGe6") as response:
            html = response.read().decode()
            self.assertIn("edge6", html)
            self.assertNotIn('href="/admin/routers/alice"', html)
        with self.admin_request(browser, "/admin/routers/edge6") as response:
            html = response.read().decode()
            self.assertIn("edge6-1.rsc", html)
            self.assertIn("SHA-256", html)
            csrf = re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"', html).group(1)
        path = "/admin/routers/edge6/files/edge6-1.rsc/download"
        with self.admin_request(browser, path) as response:
            body = response.read()
            self.assertEqual(body, b"/system identity set name=restorable\n")
            self.assertIn("attachment", response.headers["Content-Disposition"])
            self.assertEqual(response.headers["Content-Type"], "application/octet-stream")
        with self.admin_request(browser, "/admin/routers/bob") as response:
            self.assertIn(b"No available backups", response.read())
        with self.admin_request(browser, "/admin/routers/revokeme") as response:
            self.assertIn(b"revokeme-20261020000000.rsc", response.read())
        for route in (
            "/admin/routers/edge6/files/legacy.backup/download",
            "/admin/routers/edge6/files/%2e%2e%2flegacy.backup/download",
        ):
            with self.assertRaises(urllib.error.HTTPError) as rejected:
                self.admin_request(browser, route)
            self.assertEqual(rejected.exception.code, 404)
        with self.assertRaises(urllib.error.HTTPError) as csrf_error:
            self.admin_request(browser, "/admin/logout", dict(csrf="wrong"))
        self.assertEqual(csrf_error.exception.code, 403)
        private_tokens = [cookie.value for cookie in jar]
        with self.admin_request(browser, "/admin/logout", dict(csrf=csrf)) as response:
            self.assertIn(b"Admin password", response.read())
        with self.assertRaises(urllib.error.HTTPError) as unauthenticated:
            self.admin_request(browser, path)
        self.assertEqual(unauthenticated.exception.code, 401)
        info = {}
        for service in ("admin", "archive-reader"):
            container = self.compose("ps", "-q", service).stdout.strip()
            info[service] = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
            self.assertTrue(info[service]["HostConfig"]["ReadonlyRootfs"])
            self.assertEqual(info[service]["HostConfig"]["CapDrop"], ["ALL"])
            self.assertFalse(info[service]["HostConfig"].get("CapAdd"))
            self.assertFalse(info[service]["HostConfig"].get("PortBindings"))
            targets = {m["Destination"] for m in info[service]["Mounts"]}
            self.assertFalse(
                targets
                & {
                    "/incoming",
                    "/srv/sftp",
                    "/run/secrets/routers",
                    "/run/secrets/enrollment_key",
                    "/var/run/docker.sock",
                }
            )
        self.assertEqual(info["admin"]["Config"]["User"], "10001:10001")
        self.assertNotIn("/archive", {m["Destination"] for m in info["admin"]["Mounts"]})
        self.assertEqual(info["archive-reader"]["HostConfig"]["NetworkMode"], "none")
        mount = next(m for m in info["archive-reader"]["Mounts"] if m["Destination"] == "/archive")
        self.assertFalse(mount["RW"])
        self.assertFalse(any(e.startswith("ADMIN_PASSWORD=") for e in info["archive-reader"]["Config"]["Env"]))
        logs = self.compose("logs", "--no-color").stdout
        for secret in [self.admin_password] + private_tokens:
            self.assertNotIn(secret, logs)

    def test_14_admin_restart_revokes_sessions_and_download_is_immutable(self):
        browser, _ = self.admin_login()
        self.compose("restart", "admin")
        for _ in range(40):
            try:
                with self.admin_request(browser, "/admin/") as response:
                    if b"Admin password" in response.read():
                        break
            except urllib.error.HTTPError:
                pass
            time.sleep(0.25)
        else:
            self.fail("Admin session survived restart")
        self.exec_python(
            "archive-reader",
            "from pathlib import Path; p=Path('/archive/sftp/edge6/edge6-1.rsc'); assert p.stat().st_mode & 0o777 == 0o400",
        )
        browser, _ = self.admin_login()
        with self.admin_request(browser, "/admin/routers/edge6/files/edge6-1.rsc/download") as response:
            self.assertEqual(
                hashlib.sha256(response.read()).hexdigest(),
                hashlib.sha256(b"/system identity set name=restorable\n").hexdigest(),
            )

    def test_14a_admin_100_mib_https_download_uses_bounded_memory(self):
        expected = self.exec_python(
            "collector",
            """from pathlib import Path
from datetime import datetime, timezone
import hashlib, os, sys
sys.path.insert(0, '/usr/local/lib/mkbackup')
from collector import exclusive_json
p=Path('/archive/sftp/edge6/edge6-20261020000000.rsc')
block=b'x'*(64*1024)
digest=hashlib.sha256()
with p.open('wb') as output:
 for _ in range(1600):
  output.write(block)
  digest.update(block)
p.chmod(0o400)
fd=os.open(p.parent/'.receipts', os.O_RDONLY|os.O_DIRECTORY)
try:
 exclusive_json(fd, p.name+'.json', dict(version=1,router='edge6',filename=p.name,size=p.stat().st_size,sha256=digest.hexdigest(),archived_at=datetime.now(timezone.utc).isoformat()))
finally:
 os.close(fd)
print(digest.hexdigest())""",
        ).stdout.strip()

        def resident(service, program):
            result = self.exec_python(
                service,
                "from pathlib import Path; total=0\n"
                "for p in Path('/proc').iterdir():\n"
                " if not p.name.isdigit(): continue\n"
                " try:\n"
                "  args=(p/'cmdline').read_bytes().split(bytes([0]))\n"
                f"  if len(args)>1 and args[1].endswith({program.encode()!r}):\n"
                "   total+=int(next(line.split()[1] for line in (p/'status').read_text().splitlines() if line.startswith('VmRSS:')))\n"
                " except (OSError,StopIteration): pass\n"
                "print(total*1024)",
            )
            return int(result.stdout.strip())

        browser, _ = self.admin_login()
        before = resident("admin", "/usr/bin/gunicorn") + resident("archive-reader", "/archive_reader.py")
        self.assertGreater(before, 0)
        digest, total = hashlib.sha256(), 0
        with self.admin_request(browser, "/admin/routers/edge6/files/edge6-20261020000000.rsc/download") as response:
            self.assertEqual(int(response.headers["Content-Length"]), 100 * 1024 * 1024)
            while True:
                block = response.read(64 * 1024)
                if not block:
                    break
                digest.update(block)
                total += len(block)
        after = resident("admin", "/usr/bin/gunicorn") + resident("archive-reader", "/archive_reader.py")
        self.assertEqual(total, 100 * 1024 * 1024)
        self.assertEqual(digest.hexdigest(), expected)
        self.assertLess(after - before, 32 * 1024 * 1024)

    def test_14b_admin_startup_rejects_missing_or_short_password(self):
        for value in ("", "short"):
            result = self.compose(
                "run", "--rm", "--no-deps", "-T", "-e", "ADMIN_PASSWORD=" + value, "admin", check=False
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Admin startup refused", result.stderr + result.stdout)

    def test_14c_admin_enrollment_and_reissue_preserve_open_uploads(self):
        browser, _ = self.admin_login()
        before = {service: self.compose("ps", "-q", service).stdout.strip() for service in ("sftp", "ftp", "collector")}
        listener = self.exec_python(
            "sftp", "from pathlib import Path; print(Path('/run/sshd.pid').read_text().strip())"
        ).stdout.strip()
        held = self.client("bob")
        handle = held.open("/upload/live-enroll.rsc")
        held.write(handle, b"before-")
        ftp = self.ftp()
        ftp.voidcmd("TYPE I")
        data = ftp.transfercmd("STOR /upload/live-enroll.rsc")
        self.addCleanup(data.close)
        data.sendall(b"before-")
        secrets_seen = []

        def enroll(name, major, reissue=False):
            path = "/admin/enroll?router=" + name if reissue else "/admin/enroll?major=" + str(major)
            with self.admin_request(browser, path) as response:
                html = response.read().decode()
            fields = dict(re.findall(r'name="([^"<>]+)"[^>]*value="([^"<>]*)"', html))
            fields.update(
                name=name, host="127.0.0.1", port=str(self.ftp_port if major == 6 else self.port), job_owner="admin"
            )
            fields = {
                key: fields[key] for key in ("csrf", "request", "action", "major", "name", "host", "port", "job_owner")
            }
            with self.admin_request(browser, "/admin/enroll", fields) as response:
                job_url = response.geturl()
                response.read()
            with self.admin_request(browser, "/admin/enroll", fields) as response:
                self.assertEqual(response.geturl(), job_url)
                response.read()
            job = job_url.rsplit("/", 1)[1]
            for _ in range(100):
                with self.admin_request(browser, "/admin/enrollments/" + job) as response:
                    status = response.read()
                if b"Show installation commands once" in status:
                    break
                self.assertNotIn(b"<strong>failed</strong>", status)
                time.sleep(0.2)
            else:
                self.fail("Enrollment did not complete")
            route = "/admin/enrollments/" + job + "/instructions"
            with self.admin_request(browser, route, dict(csrf=fields["csrf"])) as response:
                self.assertIn("no-store", response.headers["Cache-Control"])
                commands = response.read().decode()
            token = re.search(r"Bearer ([A-Za-z0-9_-]{43})", commands).group(1)
            secrets_seen.append(token)
            with self.assertRaises(urllib.error.HTTPError) as shown:
                self.admin_request(browser, route, dict(csrf=fields["csrf"]))
            self.assertEqual(shown.exception.code, 409)
            return token, fields["csrf"]

        old_token, _ = enroll("web6", 6)
        token, csrf = enroll("web6", 6, reissue=True)
        with self.assertRaises(urllib.error.HTTPError):
            self.fetch("/", old_token)
        with self.fetch("/routeros6.rsc", token) as response:
            installer = response.read().decode()
        credentials = re.search(r'contents="([A-Za-z0-9_-]{43})\\n([A-Za-z0-9_-]{43})\\n"', installer)
        password, status_token = credentials.groups()
        secrets_seen += [password, status_token]
        payload = b"/system identity set name=web6-simulation\n"
        with self.ftp("web6", password) as uploaded:
            uploaded.storbinary("STOR /upload/web6-20261020030500.rsc", io.BytesIO(payload))
            uploaded.storbinary(
                "STOR /upload/web6-20261020030500.rsc.done.json",
                io.BytesIO(json.dumps(dict(version=1, filename="web6-20261020030500.rsc", size=len(payload))).encode()),
            )
        self.archived("web6-20261020030500.rsc", payload, "web6")
        with self.fetch("/v1/receipts/web6-20261020030500.rsc", status_token) as response:
            self.assertTrue(response.read().startswith(b"ARCHIVED "))
        with self.assertRaises(urllib.error.HTTPError) as delivered:
            self.admin_request(browser, "/admin/enroll?router=web6")
        self.assertEqual(delivered.exception.code, 409)

        token, _ = enroll("web7", 7)
        with self.fetch("/routeros7.rsc", token) as response:
            installer = response.read().decode()
        private = re.search(r'contents="(-----BEGIN RSA PRIVATE KEY-----.*?)"', installer).group(1)
        key = self.folder / "web7.pem"
        key.write_text(json.loads('"' + private + '"'))
        key.chmod(0o600)
        client = SFTP(self.port, key, self.known_hosts, "web7")
        self.addCleanup(client.close)
        payload = b"/system identity set name=web7-simulation\n"
        client.put("/upload/web7-20261020030500.rsc", payload)
        client.put(
            "/upload/web7-20261020030500.rsc.done.json",
            json.dumps(dict(version=1, filename="web7-20261020030500.rsc", size=len(payload))).encode(),
        )
        self.archived("web7-20261020030500.rsc", payload, "web7")

        held.write(handle, b"after", offset=7)
        held.close_handle(handle)
        held.put(
            "/upload/live-enroll.rsc.done.json",
            json.dumps(dict(version=1, filename="live-enroll.rsc", size=12)).encode(),
        )
        data.sendall(b"after")
        data.close()
        ftp.voidresp()
        ftp.storbinary(
            "STOR /upload/live-enroll.rsc.done.json",
            io.BytesIO(json.dumps(dict(version=1, filename="live-enroll.rsc", size=12)).encode()),
        )
        self.archived("live-enroll.rsc", b"before-after", "bob")
        self.archived("live-enroll.rsc", b"before-after", "legacy")
        self.assertEqual(before, {service: self.compose("ps", "-q", service).stdout.strip() for service in before})
        self.assertEqual(
            listener,
            self.exec_python(
                "sftp", "from pathlib import Path; print(Path('/run/sshd.pid').read_text().strip())"
            ).stdout.strip(),
        )
        for service in ("admin", "enrollment", "provisioner"):
            container = self.compose("ps", "-q", service).stdout.strip()
            info = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
            destinations = {entry["Destination"] for entry in info["Mounts"]}
            self.assertFalse(destinations & {"/archive", "/incoming", "/srv/sftp", "/var/run/docker.sock"})
            if service in ("admin", "enrollment"):
                self.assertFalse(
                    destinations
                    & {"/var/lib/mkbackup-enrollment", "/run/secrets/enrollment_key", "/config", "/ftp-config"}
                )
        logs = self.compose("logs", "--no-color").stdout
        for secret in secrets_seen:
            self.assertNotIn(secret, logs)

    def test_15_haproxy_throttles_login_by_source_not_forwarded_headers(self):
        # Refresh only the disposable edge's counters; all requests originate here.
        self.compose("restart", "haproxy")
        browser, _ = self.browser()
        for _ in range(40):
            try:
                with self.admin_request(browser, "/admin/login") as response:
                    html = response.read().decode()
                break
            except (OSError, urllib.error.URLError):
                time.sleep(0.25)
        csrf = re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"', html).group(1)
        for attempt in range(11):
            with self.assertRaises(urllib.error.HTTPError) as rejected:
                self.admin_request(
                    browser,
                    "/%61dmin/login" if attempt % 2 else "/admin/login",
                    dict(csrf=csrf, password="wrong"),
                    headers={"X-Forwarded-For": f"192.0.2.{attempt + 1}"},
                )
            self.assertEqual(rejected.exception.code, 429 if attempt == 10 else (401 if attempt == 0 else 403))


if __name__ == "__main__":
    unittest.main(verbosity=2)
