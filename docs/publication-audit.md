# Publication audit — 2026-10-20

Scope: source files, legacy Git history, file references, administration and
enrollment code, Docker configuration, RouterOS templates and public documentation.
The initial audit did not create a GitHub repository or push code. Existing local
credentials and archive volumes were preserved. The enrollment follow-up below
adds a planned deployment migration before public publication.

## Findings and changes

| Priority | Finding | Resolution |
| --- | --- | --- |
| Critical | Legacy `virtusers.txt` credentials survive in five historical revisions. Default Gitleaks rules missed this alternating-line database. | Added a dedicated detection rule and a history guard. Publication uses a history-free source export. The original private history remains unsafe to push publicly; rotate old credentials wherever reused. |
| Medium | Admin password configuration could diverge between `.env` and a local override; the management CLI accepted only one environment file. | Added repeatable `--env-file` arguments preserving Compose precedence, with regression coverage and consistent documentation. |
| Medium | An abandoned, disabled RouterOS 6 SFTP experiment coexisted with the supported v6 FTP installer. | Removed its template/rendering branch and obsolete instructions. Manual bundles accept v7 SFTP identities only; attempting v6 or an FTP identity is rejected. |
| Medium | No source publication gate, CI, license or vulnerability reporting guidance. | Added MIT licensing, read-only GitHub CI, SHA-pinned checkout, redacted history scanning, source export checks, contribution/security policies and dependency update configuration. |
| Low | Generic ignore boilerplate did not describe current private artifacts. | Replaced it with explicit environment/key/database/backup/cache/export rules, while retaining `.env.example`. Runtime image context remains an explicit allowlist. |
| Low | Unused imports, inconsistent import ordering and dense formatting obscured review. | Removed unused imports; added Ruff correctness/import/bug checks and formatting. Exception translation explicitly suppresses internal causes at public error boundaries. |
| Low | Public examples contained a deployment-specific domain and image metadata included a personal email. | Replaced the domain with `mkbackup.example.com` and removed the maintainer email label. Private local deployment settings were unchanged. |
| Low | Runtime command lookup relied on `PATH` for OpenSSL and ssh-keygen. | Container provisioning now uses fixed executable paths. Host CLI subprocesses remain argument arrays using installed administrator tools. |

## Orphan inventory

The former `mkbackup` launcher, `supervisord.conf`, `virtusers.txt` and old
`vsftpd.conf` are absent from the working tree and excluded from the public export.
Their tracked deletions must remain part of any private cleanup commit. The active
FTP configuration is `vsftpd-mkbackup.conf`, used by `container/ftp.py`.

The disabled `mikrotik/upload-routeros6.rsc.in` experiment was removed. The v6
installer is rendered by the shared `container/routeros.py` (with a CLI compatibility import) using `mikrotik/install.rsc.in`,
`job-export.rsc.in` and the shared clock helper. The v7 manual upload template
remains because `manage.py bundle` references it.

All remaining Python modules have imports or explicit runtime/documented
entrypoints. The inventory CSV is an empty operator template; the native timestamp
fixture is referenced by the validation guide. `.DS_Store`, Python caches, the
local demo backup and private enrollment/runtime files are excluded from export.
No production data or local secrets were deleted.

## Security review limits

Bandit's reviewed exceptions are the container-local `/dev/log` Unix socket
(vsftpd workers drop privileges and must send syslog) and the hard-coded loopback
HTTP health check (no untrusted URL). Low-severity subprocess findings were
reviewed: callers use argument arrays and fixed container executables or trusted
administrator tools. Broad exception handlers at WSGI/RPC/startup boundaries hide
credential-bearing internals; cleanup handlers re-raise errors.

FTP remains plaintext by design for v6. The upstream HTTPS/HAProxy firewall,
storage quotas, firmware capabilities, real hardware restoration and historical
credential rotation remain operator responsibilities. Secret scanning and static
analysis are not proof that no vulnerabilities exist. No container CVE scanner
or new physical-router pilot was performed in this audit.

## Verification

The publication candidate is checked with Ruff, Bandit, source/link validation,
shell syntax, Compose validation, a fresh application image, all unit tests and
the Docker/HAProxy integration suite. Results are recorded in
[validation.md](validation.md). The exported bytes are scanned separately with
Gitleaks, including the custom legacy-credential rule. The original history is
expected to fail both the filename guard and custom secret scan.

## Admin enrollment follow-up

Enrollment is now an authenticated admin workflow, backed by an internal
provisioner with separate public/admin/CLI socket interfaces. The public web
gateway no longer mounts encryption keys or the enrollment database. Routine
enrollment refreshes NSS, authorization and collector configuration without
container/listener restarts. CLI revocation still terminates existing sessions.
One-time migration imports stable identities, existing hashes and enrollment
state; imported accounts cannot be reissued through the UI. Delivery flags and
reissue checks share transactional SQLite state. The public source export was
regenerated after this change; use the latest export for GitHub publication.

Native GitHub x86-64 validation additionally found two missing vsftpd seccomp
rules. `patches/vsftpd-seccomp.patch` adds only the demonstrated passive-socket
option and relative-sleep operation. The Docker build uses Ubuntu's authenticated
source package and package build flags, then copies its packaged binary into the
runtime image. The sandbox is not disabled; no extra runtime capability is added.
The source patch must be reviewed/refreshed if a future Ubuntu update changes its
context. Third-party vsftpd source retains its distribution license.
