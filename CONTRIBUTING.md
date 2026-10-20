# Contributing

Use Python 3.9+ for administration/tests and Docker with Compose v2 for the runtime.
Use synthetic accounts and disposable test volumes. Never commit router exports,
private keys, enrollment tokens, environment files or populated fleet inventories.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/ruff check container scripts tests
.venv/bin/ruff format --check container scripts tests
.venv/bin/bandit -r container scripts -ll
python3 scripts/publication.py check
docker build -t mkbackup-sftp-test:local .
docker run --rm --network none --read-only --tmpfs /tmp:rw,size=256m \
  --entrypoint python3 -v "$PWD:/workspace:ro" -w /workspace \
  mkbackup-sftp-test:local -m unittest discover -s tests -p 'test_*.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 tests/integration.py
```

Ruff checks correctness, unused imports, import ordering and common Python bugs;
its formatter keeps the standalone scripts readable. Bandit's medium/high gate
has narrowly documented exceptions for the fixed loopback health check and the
container-local vsftpd syslog socket. Subprocesses use argument arrays, never a
shell. Runtime executable paths are fixed; host administration uses installed tools.

The integration suite owns only its randomly named projects/volumes. Tests require
unused local ports and access to pinned container images. Do not point tests at
production volumes. Native RouterOS firmware/hardware pilots are separate from
Python and Docker checks; describe validation limits in pull requests.

Use small focused changes, describe the resulting behavior and list relevant
checks. Changes to archive publication, retention, auth or installer state need
regression coverage. Run [publication checks](docs/publication.md) before release.
Contributions use the repository's [MIT license](LICENSE).
