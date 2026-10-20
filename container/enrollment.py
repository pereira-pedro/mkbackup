"""Encrypted, single-download installers and separately scoped receipt credentials."""

import hashlib
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from common import NAME
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")


def token_hash(value):
    if not isinstance(value, str) or not TOKEN.fullmatch(value):
        raise ValueError("Invalid credential")
    return hashlib.sha256(value.encode("ascii")).hexdigest()


class Store:
    def __init__(self, directory="/var/lib/mkbackup-enrollment", keyfile="/run/mkbackup/web.key"):
        self.directory = Path(directory)
        self.keyfile = Path(keyfile)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS deployments (
                    hash TEXT PRIMARY KEY, router TEXT NOT NULL, major INTEGER NOT NULL,
                    expires REAL NOT NULL, state TEXT NOT NULL, nonce BLOB, ciphertext BLOB);
                CREATE TABLE IF NOT EXISTS status_auth (
                    hash TEXT PRIMARY KEY, router TEXT UNIQUE NOT NULL);
                CREATE INDEX IF NOT EXISTS deployment_router ON deployments(router);
                CREATE TABLE IF NOT EXISTS delivery (
                    router TEXT PRIMARY KEY, downloaded INTEGER NOT NULL DEFAULT 0);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.directory / "enrollment.sqlite3", timeout=5, isolation_level=None)
        try:
            db.execute("PRAGMA secure_delete=ON")
            db.execute("PRAGMA synchronous=FULL")
            yield db
        finally:
            db.close()

    def cipher(self):
        key = self.keyfile.read_bytes()
        if len(key) != 32:
            raise ValueError("Enrollment key must be 32 bytes")
        return AESGCM(key)

    @staticmethod
    def expire(db, now):
        db.execute(
            "UPDATE deployments SET state='expired', nonce=NULL, ciphertext=NULL WHERE state='issued' AND expires<=?",
            (now,),
        )
        db.execute("DELETE FROM deployments WHERE expires<? AND state!='issued'", (now - 30 * 86400,))

    def create(self, router, major, installer, status_token, now=None):
        now = time.time() if now is None else now
        if not NAME.fullmatch(router) or major not in (6, 7) or not 1 <= len(installer) <= 256 * 1024:
            raise ValueError("Invalid deployment")
        status_hash = token_hash(status_token)
        token = secrets.token_urlsafe(32)
        hashed = token_hash(token)
        nonce = secrets.token_bytes(12)
        ciphertext = self.cipher().encrypt(nonce, installer, (router + ":" + str(major)).encode())
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.expire(db, now)
            db.execute(
                "UPDATE deployments SET state='revoked', nonce=NULL, ciphertext=NULL WHERE router=? AND state='issued'",
                (router,),
            )
            db.execute("DELETE FROM status_auth WHERE router=?", (router,))
            db.execute("INSERT INTO status_auth VALUES (?,?)", (status_hash, router))
            db.execute(
                "INSERT INTO deployments VALUES (?,?,?,?,?,?,?)",
                (hashed, router, major, now + 600, "issued", nonce, ciphertext),
            )
            db.commit()
        return dict(token=token, expires_at=now + 600)

    def redeem(self, token, major=None, now=None):
        now = time.time() if now is None else now
        hashed = token_hash(token)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.expire(db, now)
            row = db.execute(
                "SELECT router,major,state,nonce,ciphertext FROM deployments WHERE hash=?", (hashed,)
            ).fetchone()
            if not row or row[2] != "issued" or (major is not None and row[1] != major):
                db.commit()
                raise ValueError("Unavailable deployment")
            plaintext = self.cipher().decrypt(row[3], row[4], (row[0] + ":" + str(row[1])).encode())
            db.execute("UPDATE deployments SET state='downloaded',nonce=NULL,ciphertext=NULL WHERE hash=?", (hashed,))
            db.execute("INSERT INTO delivery VALUES (?,1) ON CONFLICT(router) DO UPDATE SET downloaded=1", (row[0],))
            # Commit before returning bytes. A dropped connection cannot replay.
            db.commit()
        return plaintext

    def authorized_router(self, token):
        with self.connect() as db:
            row = db.execute("SELECT router FROM status_auth WHERE hash=?", (token_hash(token),)).fetchone()
        if row is None:
            raise ValueError("Invalid credential")
        return row[0]

    def revoke(self, router):
        if not NAME.fullmatch(router):
            raise ValueError("Invalid router")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE deployments SET state='revoked',nonce=NULL,ciphertext=NULL WHERE router=?", (router,))
            db.execute("DELETE FROM status_auth WHERE router=?", (router,))
            db.commit()

    def listing(self):
        with self.connect() as db:
            self.expire(db, time.time())
            return [
                dict(router=row[0], routeros_major=row[1], expires_at=row[2], state=row[3])
                for row in db.execute(
                    "SELECT router,major,expires,state FROM deployments ORDER BY expires DESC LIMIT 1000"
                )
            ]
