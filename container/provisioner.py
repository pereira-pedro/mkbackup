"""Single authority for identities, encrypted installers and serialized enrollment jobs."""

import base64
import ipaddress
import json
import os
import re
import secrets
import socketserver
import subprocess
import threading
import time
from pathlib import Path

from common import NAME, atomic_json, decode_json, fingerprint, parse_ftp_passwords, parse_routers, public_key
from control_rpc import ADMIN_SOCKET, CLI_SOCKET, PUBLIC_SOCKET, ControlError, receive, send
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from enrollment import Store
from routeros import render

RESERVED = {"root", "nobody", "sshd", "ftp"}
ID = re.compile(r"[a-f0-9]{64}")


class Provisioner:
    def __init__(
        self,
        store,
        seed,
        passwords,
        host_key,
        config="/config",
        ftp_config="/ftp-config",
        acks="/acks",
        base_url="https://mkbackup.example.com",
        defaults=None,
    ):
        self.store, self.host_key = store, public_key(host_key)
        self.config, self.ftp_config, self.acks = Path(config), Path(ftp_config), Path(acks)
        self.base_url = base_url.rstrip("/")
        self.defaults = defaults or dict(host="", ftp_port=15101, sftp_port=15100)
        self.mutations = threading.Lock()
        with store.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS registry (id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL, routers TEXT NOT NULL, passwords TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, request TEXT UNIQUE NOT NULL, owner TEXT NOT NULL, router TEXT NOT NULL, spec TEXT NOT NULL, action TEXT NOT NULL, state TEXT NOT NULL, error TEXT, created REAL NOT NULL, expires REAL, nonce BLOB, result BLOB);
            """)
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM registry").fetchone():
                routers = parse_routers(json.dumps(seed))
                parse_ftp_passwords(json.dumps(passwords).encode())
                db.execute("INSERT INTO registry VALUES (1,1,?,?)", (json.dumps(routers), json.dumps(passwords)))
                for router in routers:
                    db.execute("INSERT OR REPLACE INTO delivery VALUES (?,1)", (router["name"],))
            db.execute(
                "UPDATE jobs SET state='failed',error='Provisioning interrupted; reissue the unused installer',nonce=NULL,result=NULL WHERE state='running'"
            )
            db.commit()
        self.publish()

    def registry(self, db=None):
        if db is None:
            with self.store.connect() as connection:
                return self.registry(connection)
        row = db.execute("SELECT generation,routers,passwords FROM registry WHERE id=1").fetchone()
        return row[0], json.loads(row[1]), json.loads(row[2])

    def save(self, db, routers, passwords):
        parse_routers(json.dumps(dict(version=2, routers=routers)))
        parse_ftp_passwords(json.dumps(passwords).encode())
        db.execute(
            "UPDATE registry SET generation=generation+1,routers=?,passwords=? WHERE id=1",
            (json.dumps(routers), json.dumps(passwords)),
        )

    def publish(self):
        generation, routers, passwords = self.registry()
        atomic_json(self.ftp_config / "passwords.json", dict(generation=generation, passwords=passwords))
        atomic_json(
            self.config / "routers.json",
            dict(generation=generation, registry=dict(version=2, routers=routers)),
            mode=0o644,
        )
        return generation

    def health(self):
        with self.store.connect() as db:
            self.store.expire(db, time.time())
            db.execute("UPDATE jobs SET nonce=NULL,result=NULL WHERE expires<=?", (time.time(),))
            db.execute(
                "DELETE FROM jobs WHERE created<? AND state NOT IN ('queued','running')", (time.time() - 30 * 86400,)
            )
        return dict(ready=True)

    def validate(self, spec):
        if not isinstance(spec, dict) or set(spec) != {"name", "major", "host", "port", "job_owner"}:
            raise ControlError("Invalid enrollment fields")
        name, major = spec["name"], spec["major"]
        if (
            not isinstance(name, str)
            or not NAME.fullmatch(name)
            or name in RESERVED
            or type(major) is not int
            or major not in (6, 7)
        ):
            raise ControlError("Invalid router name or RouterOS profile")
        try:
            ipaddress.IPv4Address(spec["host"])
        except (ValueError, TypeError):
            raise ControlError("Enter the router-reachable server IPv4 address") from None
        if (
            type(spec["port"]) is not int
            or not 1 <= spec["port"] <= 65535
            or not isinstance(spec["job_owner"], str)
            or not NAME.fullmatch(spec["job_owner"])
        ):
            raise ControlError("Invalid transport port or RouterOS job owner")
        # Use exactly the same URL/owner validation as the actual renderer.
        render(
            dict(name=name, max_bytes=104857600),
            6,
            spec["host"],
            spec["port"],
            self.base_url,
            spec["job_owner"],
            "s" * 43,
            password="p" * 43,
        )
        return spec

    def enqueue(self, spec, owner, request, action="create", replace=False):
        self.validate(spec)
        if (
            not isinstance(owner, str)
            or not ID.fullmatch(owner)
            or not isinstance(request, str)
            or not ID.fullmatch(request)
            or action not in ("create", "reissue", "rotate")
        ):
            raise ControlError("Invalid enrollment request")
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT id,owner,spec,action FROM jobs WHERE request=?", (request,)).fetchone()
            if existing:
                if existing[1:] != (owner, json.dumps(spec, sort_keys=True), action):
                    raise ControlError("Enrollment request conflicts", 409)
                return dict(id=existing[0])
            if db.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','running')").fetchone()[0] >= 16:
                raise ControlError("Provisioning queue is full; try again later", 503)
            _, routers, _ = self.registry(db)
            router = next((row for row in routers if row["name"] == spec["name"]), None)
            if db.execute(
                "SELECT 1 FROM jobs WHERE router=? AND state IN ('queued','running')", (spec["name"],)
            ).fetchone():
                raise ControlError("Enrollment already in progress for this router", 409)
            if action == "create" and router is not None:
                raise ControlError("Router already exists; use eligible reissue or CLI recovery", 409)
            if action != "create":
                if router is None or router["transport"] != ("ftp" if spec["major"] == 6 else "sftp"):
                    raise ControlError("Router profile cannot be changed", 409)
                delivery = db.execute("SELECT downloaded FROM delivery WHERE router=?", (spec["name"],)).fetchone()
                if action == "reissue" and (delivery is None or delivery[0]):
                    raise ControlError("Installer already delivered or router imported; use CLI recovery/rotation", 409)
                if action == "rotate" and not replace:
                    raise ControlError("Explicit CLI rotation required", 409)
            if action == "create":
                uid = max([9999] + [row["uid"] for row in routers]) + 1
                if uid > 60000 or len(routers) >= 1000:
                    raise ControlError("Router identity capacity reached", 409)
                routers.append(
                    dict(
                        name=spec["name"],
                        uid=uid,
                        keys=[],
                        enabled=False,
                        transport="ftp" if spec["major"] == 6 else "sftp",
                        max_bytes=104857600,
                        expected_interval_seconds=86400,
                    )
                )
                _, _, passwords = self.registry(db)
                self.save(db, routers, passwords)
                db.execute("INSERT INTO delivery VALUES (?,0)", (spec["name"],))
            # This transaction serializes against redeem(), including its delivery flag.
            db.execute(
                "UPDATE deployments SET state='revoked',nonce=NULL,ciphertext=NULL WHERE router=? AND state='issued'",
                (spec["name"],),
            )
            db.execute(
                "UPDATE jobs SET nonce=NULL,result=NULL,state='superseded' WHERE router=? AND state='ready'",
                (spec["name"],),
            )
            job = secrets.token_hex(32)
            db.execute(
                "INSERT INTO jobs VALUES (?,?,?,?,?,?,'queued',NULL,?,NULL,NULL,NULL)",
                (job, request, owner, spec["name"], json.dumps(spec, sort_keys=True), action, time.time()),
            )
            db.commit()
        print(json.dumps(dict(event="enrollment_queued", router=spec["name"], job=job)), flush=True)
        return dict(id=job)

    def jobs(self, page=1):
        if type(page) is not int or not 1 <= page <= 1000000:
            raise ControlError("Invalid page")
        with self.store.connect() as db:
            rows = db.execute(
                "SELECT id,router,state,error,created FROM jobs ORDER BY created DESC LIMIT 50 OFFSET ?",
                ((page - 1) * 50,),
            ).fetchall()
            routers = self.registry(db)[1]
            deliveries = dict(db.execute("SELECT router,downloaded FROM delivery"))
        return dict(
            jobs=[dict(zip(("id", "router", "state", "error", "created"), row)) for row in rows],
            routers=[
                dict(
                    name=row["name"],
                    major=6 if row["transport"] == "ftp" else 7,
                    enabled=row["enabled"],
                    reissuable=deliveries.get(row["name"], 1) == 0,
                )
                for row in routers
            ],
            defaults=dict(self.defaults, base_url=self.base_url),
        )

    def job(self, id, owner):
        if not isinstance(id, str) or not ID.fullmatch(id):
            raise ControlError("Job not found", 404)
        with self.store.connect() as db:
            row = db.execute("SELECT router,state,error,expires,owner,result FROM jobs WHERE id=?", (id,)).fetchone()
        if row is None or row[4] != owner:
            raise ControlError("Job not found", 404)
        return dict(
            id=id,
            router=row[0],
            state=row[1],
            error=row[2],
            expires=row[3],
            instructions_available=row[5] is not None and row[3] > time.time(),
        )

    def instructions(self, id, owner):
        self.job(id, owner)
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT nonce,result,expires FROM jobs WHERE id=? AND owner=?", (id, owner)).fetchone()
            if row is None or row[1] is None or row[2] <= time.time():
                raise ControlError("Instructions were already shown or expired; reissue an unused installer", 409)
            result = json.loads(self.store.cipher().decrypt(row[0], row[1], id.encode()))
            db.execute("UPDATE jobs SET nonce=NULL,result=NULL WHERE id=?", (id,))
            db.commit()
        return result

    def wait_applied(self, generation, transport, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready = True
            for service in (transport, "collector"):
                try:
                    ack = decode_json((self.acks / (service + ".json")).read_bytes())
                    ready = (
                        ready
                        and ack["generation"] >= generation
                        and ack["healthy"]
                        and time.time() - ack["heartbeat"] < 180
                    )
                except (OSError, ValueError, KeyError):
                    ready = False
            if ready:
                return
            time.sleep(0.2)
        raise ControlError(
            "Account/collector refresh did not complete; check service health and reissue the unused installer", 503
        )

    def process_one(self):
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT id,spec,action FROM jobs WHERE state='queued' ORDER BY created LIMIT 1").fetchone()
            if row is None:
                return False
            db.execute("UPDATE jobs SET state='running' WHERE id=?", (row[0],))
            db.commit()
        job, encoded, action = row
        spec = json.loads(encoded)
        try:
            with self.mutations:
                password = secrets.token_urlsafe(32) if spec["major"] == 6 else None
                status_token = secrets.token_urlsafe(32)
                private = key = None
                if spec["major"] == 7:
                    generated = rsa.generate_private_key(public_exponent=65537, key_size=3072)
                    private = generated.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.TraditionalOpenSSL,
                        serialization.NoEncryption(),
                    ).decode()
                    key = public_key(
                        generated.public_key()
                        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
                        .decode()
                    )
                with self.store.connect() as db:
                    db.execute("BEGIN IMMEDIATE")
                    _, routers, passwords = self.registry(db)
                    router = next(item for item in routers if item["name"] == spec["name"])
                    if key:
                        router["keys"] = router["keys"] + [key] if action == "rotate" else [key]
                    if password:
                        passwords[router["name"]] = (
                            subprocess.check_output(
                                ["/usr/bin/openssl", "passwd", "-6", "-stdin"], input=password.encode()
                            )
                            .decode()
                            .strip()
                        )
                    router["enabled"] = True
                    self.save(db, routers, passwords)
                    db.commit()
                installer = render(
                    router,
                    spec["major"],
                    spec["host"],
                    spec["port"],
                    self.base_url,
                    spec["job_owner"],
                    status_token,
                    private,
                    self.host_key,
                    password,
                )
                generation = self.publish()
                self.wait_applied(generation, router["transport"])
                issued = self.store.create(router["name"], spec["major"], installer, status_token)
                result = dict(
                    token=issued["token"],
                    expires_at=issued["expires_at"],
                    base_url=self.base_url,
                    router=router["name"],
                )
                nonce = secrets.token_bytes(12)
                encrypted = self.store.cipher().encrypt(nonce, json.dumps(result).encode(), job.encode())
                with self.store.connect() as db:
                    db.execute(
                        "UPDATE jobs SET state='ready',expires=?,nonce=?,result=? WHERE id=?",
                        (issued["expires_at"], nonce, encrypted, job),
                    )
        except Exception as error:
            # Never log key material, passwords, renderer inputs or exception payloads.
            message = (
                str(error)
                if isinstance(error, ControlError)
                else "Provisioning failed; check service health and reissue the unused installer"
            )
            with self.store.connect() as db:
                db.execute("UPDATE jobs SET state='failed',error=?,nonce=NULL,result=NULL WHERE id=?", (message, job))
            print(json.dumps(dict(event="enrollment_failed", job=job, error_type=type(error).__name__)), flush=True)
        return True

    def worker(self):
        while True:
            if not self.process_one():
                time.sleep(0.2)

    def mutate(self, action, **parameters):
        with self.mutations, self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            _, routers, passwords = self.registry(db)
            name = parameters.get("name")
            if not isinstance(name, str) or not NAME.fullmatch(name) or name in RESERVED:
                raise ControlError("Invalid router name")
            router = next((row for row in routers if row["name"] == name), None)
            if action == "enroll":
                key = public_key(parameters["public_key"])
                if router is None:
                    router = dict(
                        name=name,
                        uid=parameters.get("uid") or max([9999] + [row["uid"] for row in routers]) + 1,
                        keys=[],
                        enabled=True,
                        transport="sftp",
                        max_bytes=104857600,
                        expected_interval_seconds=86400,
                    )
                    routers.append(router)
                    db.execute("INSERT INTO delivery VALUES (?,1)", (name,))
                if router["transport"] != "sftp" or parameters.get("uid") not in (None, router["uid"]):
                    raise ControlError("Router transport/UID cannot change")
                if key not in router["keys"]:
                    router["keys"].append(key)
                router["enabled"] = True
                for field in ("max_bytes", "expected_interval_seconds"):
                    if parameters.get(field) is not None:
                        router[field] = parameters[field]
            elif action in ("disable", "revoke-key", "revoke"):
                if router is None:
                    raise ControlError("Router not found", 404)
                if action == "revoke-key":
                    retained = [key for key in router["keys"] if fingerprint(key) != parameters["fingerprint"]]
                    if retained == router["keys"]:
                        raise ControlError("Key fingerprint not found")
                    router["keys"] = retained
                    router["enabled"] = bool(retained)
                else:
                    router["enabled"] = False
                if action == "revoke":
                    db.execute(
                        "UPDATE deployments SET state='revoked',nonce=NULL,ciphertext=NULL WHERE router=?", (name,)
                    )
                    db.execute("DELETE FROM status_auth WHERE router=?", (name,))
                    db.execute("UPDATE jobs SET nonce=NULL,result=NULL,state='superseded' WHERE router=?", (name,))
            else:
                raise ControlError("Unknown mutation")
            self.save(db, routers, passwords)
            db.commit()
        return dict(router=router)

    def dispatch(self, role, operation, **parameters):
        if operation == "health" and not parameters:
            return self.health()
        if role == "public":
            if operation == "redeem" and set(parameters) == {"token", "major"} and parameters["major"] in (None, 6, 7):
                return dict(installer=base64.b64encode(self.store.redeem(**parameters)).decode())
            if operation == "authorize" and set(parameters) == {"token"}:
                return dict(router=self.store.authorized_router(parameters["token"]))
            raise ControlError("Operation not permitted", 403)
        if operation in ("create", "reissue") and set(parameters) == {"spec", "owner", "request"}:
            return self.enqueue(action=operation, **parameters)
        if operation == "list" and set(parameters) <= {"page"}:
            return self.jobs(**parameters)
        if operation in ("job", "instructions") and set(parameters) == {"id", "owner"}:
            return getattr(self, operation)(**parameters)
        if role == "cli":
            if operation == "registry" and not parameters:
                return dict(routers=self.registry()[1])
            if operation == "apply" and not parameters:
                with self.mutations:
                    return dict(generation=self.publish())
            if operation == "rotate" and set(parameters) == {"spec", "owner", "request"}:
                return self.enqueue(action="rotate", replace=True, **parameters)
            if operation == "mutate":
                return self.mutate(**parameters)
            if operation == "deployments" and not parameters:
                return self.store.listing()
        raise ControlError("Operation not permitted", 403)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            value = receive(self.request, limit=65536 if self.server.role == "cli" else 4096)
            operation = value.pop("operation", None)
            data = self.server.engine.dispatch(self.server.role, operation, **value)
            send(self.request, dict(status=200, data=data))
        except Exception as error:
            status = (
                error.status
                if isinstance(error, ControlError)
                else 400
                if isinstance(error, (ValueError, TypeError, KeyError))
                else 503
            )
            message = (
                str(error)
                if isinstance(error, ControlError)
                else "Credential unavailable"
                if status == 400
                else "Provisioning unavailable"
            )
            try:
                send(self.request, dict(status=status, error=message))
            except OSError:
                pass


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, path, role, engine):
        self.role, self.engine = role, engine
        self.slots = threading.BoundedSemaphore(16)
        path = Path(path)
        path.unlink(missing_ok=True)
        super().__init__(str(path), Handler)
        path.chmod(0o660)

    def process_request(self, request, address):
        if not self.slots.acquire(False):
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


def main():
    from common import directory, load_ftp_passwords, load_routers

    os.umask(0o077)
    seed = dict(version=2, routers=load_routers())
    passwords = load_ftp_passwords()
    host_key = Path("/run/secrets/ssh_host_rsa_public_key").read_text()
    key = Path("/run/secrets/enrollment_key").read_bytes()
    if len(key) != 32:
        raise ValueError("Invalid encryption key")
    for path in (
        "/run/mkbackup",
        "/var/lib/mkbackup-enrollment",
        "/config",
        "/ftp-config",
        "/control-admin",
        "/control-public",
    ):
        directory(path, 0o750, 10001, 10001)
    path = Path("/run/mkbackup/web.key")
    path.write_bytes(key)
    path.chmod(0o400)
    os.chown(path, 10001, 10001)
    os.setgroups([])
    os.setgid(10001)
    os.setuid(10001)
    engine = Provisioner(
        Store(),
        seed,
        passwords,
        host_key,
        base_url=os.environ.get("ENROLLMENT_BASE_URL") or "https://" + os.environ["DEPLOYMENT_HOST"],
        defaults=dict(
            host=os.environ.get("FTP_PUBLIC_ADDRESS", ""),
            ftp_port=int(os.environ.get("FTP_PORT", "15101")),
            sftp_port=int(os.environ.get("SFTP_PORT", "15100")),
        ),
    )
    servers = [
        Server(ADMIN_SOCKET, "admin", engine),
        Server(PUBLIC_SOCKET, "public", engine),
        Server(CLI_SOCKET, "cli", engine),
    ]
    threading.Thread(target=engine.worker, daemon=True).start()
    for server in servers[:-1]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    servers[-1].serve_forever()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(
            "Provisioner startup refused ("
            + type(error).__name__
            + "); check seed configuration, public host key and encryption key"
        ) from None
