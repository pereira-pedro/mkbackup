"""Start the unprivileged public HTTP gateway; it holds no enrollment secrets."""

import os


def main():
    os.chdir("/usr/local/lib/mkbackup")
    os.execv(
        "/usr/bin/gunicorn",
        [
            "/usr/bin/gunicorn",
            "--bind",
            "0.0.0.0:8080",
            "--workers",
            "2",
            "--timeout",
            "15",
            "--limit-request-line",
            "2048",
            "--limit-request-fields",
            "100",
            "--limit-request-field_size",
            "2048",
            "--error-logfile",
            "-",
            "web:application",
        ],
    )


if __name__ == "__main__":
    main()
