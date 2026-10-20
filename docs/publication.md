# Public GitHub publication

The original private source repository's history contains the legacy plaintext FTP
credential database `virtusers.txt`. Deleting it from the working tree does not
remove old commits. **Do not push this repository's existing branches or tags to
a public remote.** Rotate those historical credentials wherever they were reused.
This guide uses a new, history-free source snapshot and preserves the private
repository, environment, enrolled routers and Docker volumes.

## Validate and export

Run the checks in [CONTRIBUTING.md](../CONTRIBUTING.md), then:

```sh
python3 scripts/publication.py check
python3 scripts/publication.py history  # Expected to reject the original private history.
python3 scripts/publication.py export
```

The export creates `dist/mkbackup-public/`, `dist/mkbackup-public.zip`, and
`dist/mkbackup-public.manifest.json` with SHA-256 hashes. It refuses to overwrite
existing artifacts; use `--output dist/mkbackup-public-next` for a later export.
The explicit source allowlist includes uncommitted new code. Unknown nonignored
files, missing source, symlinks, private-key material, populated router inventory and broken documentation
links stop validation. This check complements a secret scanner; it cannot prove
the absence of every possible password.

The export excludes `.git`, `.env`, `secrets/`, credentials, enrollment bundles,
the local demo backup, caches and previous publication artifacts. Docker volumes
are outside the export. Keep the inventory CSV empty; do not copy production
addresses or router metadata into examples. All shipped endpoints are examples
and require explicit deployment configuration.

Scan the actual exported bytes with the pinned Gitleaks image:

```sh
docker run --rm --network none --read-only -v "$PWD/dist/mkbackup-public:/repo:ro" \
  ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f \
  dir /repo --config /repo/.gitleaks.toml --redact=100 --no-banner
```

The custom rule catches the old alternating username/password file that the
default token/entropy rules missed. Do not add an allowlist for that finding.
To audit the original history, use the same command with the original repository
mount and `git /repo --log-opts=--all` instead of `dir /repo`.

## Create the new repository

Only after reviewing the snapshot, initialize Git **inside the exported folder**:

```sh
cd dist/mkbackup-public
git init -b main
git add .
git commit -m "Initial public release"
python3 scripts/publication.py history
```

Review the commit and run the Gitleaks history check there. Create an empty GitHub
repository and add its URL to this new repository; never copy the original `.git`
directory or reuse its branches/tags. The preparation helper does not commit,
change remotes, create a GitHub repository, push or rewrite the original history.

Enable private vulnerability reporting, secret scanning/push protection where
available, and branch protection requiring the **Validate** workflow. Its token
has read-only permissions; checkout is SHA-pinned and does not persist credentials.
It runs source/history checks, redacted secret scanning, lint, unit tests and
the real Docker/HAProxy integration suite without production secrets.

The [MIT license](../LICENSE) applies to project code. Container packages and
third-party tools retain their own licenses. The native firmware emulator used
for historical validation is not distributed in this source export.

See [the publication audit](publication-audit.md) for findings and limits.
