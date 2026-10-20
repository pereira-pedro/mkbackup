"""Validate the password, clear volatile sessions, then start unprivileged workers."""

import os
import sys
from pathlib import Path

from admin_sessions import Sessions, password_digest


def main():
    os.umask(0o077)
    password_digest(os.environ.get("ADMIN_PASSWORD"))
    directory = Path("/run/admin")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    for suffix in ("", "-journal", "-wal", "-shm"):
        (directory / ("sessions.sqlite3" + suffix)).unlink(missing_ok=True)
    Sessions()
    os.chdir("/usr/local/lib/mkbackup")
    os.execv(
        "/usr/bin/gunicorn",
        [
            "/usr/bin/gunicorn",
            "--bind",
            "0.0.0.0:8080",
            "--workers",
            "2",
            "--worker-class",
            "gthread",
            "--threads",
            "4",
            "--timeout",
            "120",
            "--limit-request-line",
            "2048",
            "--limit-request-fields",
            "100",
            "--limit-request-field_size",
            "2048",
            "--error-logfile",
            "-",
            "admin_web:app",
        ],
    )


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit("Admin startup refused: configure ADMIN_PASSWORD (at least 16 characters) and writable session tmpfs")
