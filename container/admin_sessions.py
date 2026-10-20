"""Opaque, bounded server-side browser sessions shared by Gunicorn workers."""

import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
COOKIE = "__Secure-mkbackup_admin"
IDLE = 30 * 60
LIFETIME = 8 * 60 * 60


def password_digest(value):
    if not isinstance(value, str) or len(value) < 16 or len(value.encode()) > 1024 or "\x00" in value:
        raise ValueError("ADMIN_PASSWORD must contain 16 or more characters and at most 1024 UTF-8 bytes")
    return hashlib.sha256(value.encode()).digest()


def hashed(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


class Sessions:
    def __init__(self, directory="/run/admin", password=None):
        self.password = password_digest(os.environ.get("ADMIN_PASSWORD") if password is None else password)
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.directory / "sessions.sqlite3"
        with self.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, csrf TEXT NOT NULL, "
                "created REAL NOT NULL, seen REAL NOT NULL, authenticated INTEGER NOT NULL)"
            )
            db.execute("CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value BLOB NOT NULL)")
            db.execute("INSERT OR IGNORE INTO settings VALUES ('csrf_key', ?)", (secrets.token_bytes(32),))
            self.csrf_key = db.execute("SELECT value FROM settings WHERE name='csrf_key'").fetchone()[0]

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        try:
            self.path.chmod(0o600)
            db.execute("PRAGMA secure_delete=ON")
            yield db
        finally:
            db.close()

    @staticmethod
    def prune(db, now):
        db.execute(
            "DELETE FROM sessions WHERE seen<=? OR created<=? OR (authenticated=0 AND created<=?)",
            (now - IDLE, now - LIFETIME, now - 600),
        )

    def create(self, authenticated=False, replace=None, now=None):
        now = time.time() if now is None else now
        token = secrets.token_urlsafe(32)
        csrf = self.csrf_token(token)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.prune(db, now)
            if replace and TOKEN.fullmatch(replace):
                db.execute("DELETE FROM sessions WHERE token=?", (hashed(replace),))
            # Bound storage without allowing anonymous traffic to evict logged-in users.
            db.execute(
                "DELETE FROM sessions WHERE token IN (SELECT token FROM sessions WHERE authenticated=0 "
                "ORDER BY created DESC LIMIT -1 OFFSET 1023)"
            )
            if db.execute("SELECT count(*) FROM sessions").fetchone()[0] >= 2048:
                raise RuntimeError("Session capacity reached")
            db.execute(
                "INSERT INTO sessions VALUES (?,?,?,?,?)", (hashed(token), hashed(csrf), now, now, int(authenticated))
            )
            db.commit()
        return token, csrf

    def get(self, token, now=None):
        if not isinstance(token, str) or not TOKEN.fullmatch(token):
            return None
        now = time.time() if now is None else now
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.prune(db, now)
            row = db.execute("SELECT csrf,authenticated FROM sessions WHERE token=?", (hashed(token),)).fetchone()
            if row:
                db.execute("UPDATE sessions SET seen=? WHERE token=?", (now, hashed(token)))
            db.commit()
        return dict(csrf=row[0], authenticated=bool(row[1])) if row else None

    def revoke(self, token):
        if isinstance(token, str) and TOKEN.fullmatch(token):
            with self.connect() as db:
                db.execute("DELETE FROM sessions WHERE token=?", (hashed(token),))

    def csrf_valid(self, session, value):
        return (
            session is not None
            and isinstance(value, str)
            and TOKEN.fullmatch(value)
            and hmac.compare_digest(session["csrf"], hashed(value))
        )

    def check_password(self, value):
        return hmac.compare_digest(self.password, hashlib.sha256(value.encode()).digest())

    def csrf_token(self, token):
        # Stable per session and across workers/tabs, without storing plaintext.
        # An independent random key avoids turning public login forms into an
        # offline password-guessing oracle. It lives only in the private tmpfs DB.
        digest = hmac.digest(self.csrf_key, b"mkbackup-csrf:" + token.encode("ascii"), "sha256")
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
