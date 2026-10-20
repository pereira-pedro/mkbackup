# Deployment validation

Validation performed on 2026-10-20, using temporary accounts, certificates,
Compose projects and volumes. Production DNS, routers and backup data were not
changed. The deployment instructions are in [deployment.md](deployment.md).

## Automated repository checks

- 61 unit tests in the application image, including AES-GCM storage, one-use
  concurrent redemption, profile/scoped-token checks, expiry/revocation, retention
  calendar boundaries, read-only preview, interrupted pruning, rejected-upload
  behavior, revocation when the enrollment database is unavailable, admin sessions,
  CSRF protection, router/file pagination, unsafe archive inputs, integrity checks,
  pruning during an open download and bounded-memory 100 MiB socket streaming.
  Publication follow-up covers source export exclusion, symlinks/private keys,
  documentation links, populated fleet inventory rejection, layered environment
  precedence and removal of the v6 SFTP experiment. All 61 passed during the
  public-release audit.
- 19 Docker integration tests covering actual SFTP/FTP authentication and
  isolation, open-handle archive protection, HAProxy HTTPS termination with a test
  certificate forwarding to the production Caddy HTTP configuration, both CLI
  issuance profiles, one-use download, receipt confirmation, unprivileged web
  workers, retention after uploads and live FTP session revocation. Backend checks
  confirm HTTP on port 15102 without redirects or persistent Caddy volumes.
  Admin checks cover HTTPS login/search/download/logout, read-only archive/socket
  isolation, restart invalidation, missing/short password startup rejection, source
  IP throttling despite spoofed forwarding headers/encoded login paths, and a real
  100 MiB HTTPS download. Combined web/reader resident-memory growth stays below
  32 MiB during that download; the socket-level allocation test stays below 4 MiB.
  Browser/proxy requests with 40 headers succeed; excessive header counts and
  oversized individual fields remain rejected.
- Application image build, production Caddyfile validation, Compose profile
  validation, Python syntax parsing and shell syntax checks.

Run the commands in the README. The complete unit suite requires the application image's
`python3-cryptography` package; host-only runs need that dependency separately.
The integration suite starts only disposable localhost services and cleans all
its Compose profiles and volumes. It does not execute RouterOS itself.

## Public-release source audit

See [publication-audit.md](publication-audit.md) for the orphan-file and code review.
Ruff correctness/import/bug checks and formatting pass. Bandit's medium/high gate
passes with the two documented, narrow runtime exceptions. Source/link validation
and shell syntax checks pass. Full-history checks deliberately reject the old
private repository: the custom Gitleaks rule detects four legacy credential-line
findings, while the filename guard finds the credential file in five revisions.
This is why publication must use the exported, history-free snapshot.

## RouterOS 6.49.19 CHR emulator

Used the official `chr-6.49.19.img.zip` from MikroTik's HTTPS download server,
under an isolated QEMU x86 emulator. Its management ports were reachable only
inside the disposable lab container. This was a firmware execution test, not a
physical RouterBOARD or public-internet deployment.

The following passed with the generated v6 installer and real vsftpd/collector:

- Download with `check-certificate=yes`, an explicitly trusted RSA test CA,
  authorization header and the documented destination filename.
- Import, managed ownership checks, first redacted export, passive FTP payload
  and completion-manifest upload, SHA-256 receipt creation and HTTPS confirmation.
- Scheduler enabled only after confirmation; recurring jobs executed under the
  scheduler's actual owner/policies. The scheduled retry of an unresolved upload
  reused its original filename/counter before generating subsequent exports.
- Wrong FTP credentials exhausted the three attempts, retained exactly one
  pending local export, and recovered after restoring the credentials.
- Exactly one managed local export remained after successful runs. FTP/status
  credentials and the router's lab administrator password were absent from the
  archived exports.
- A wrong HTTPS hostname was rejected, and removing CA trust caused HTTPS to
  fail. Neither test disabled certificate validation.
- After reboot, the counter, runtime credential file and single local export
  persisted, and another job successfully archived the next numbered export.

The lab HTTPS server used Python/OpenSSL and a local RSA certificate to drive
the native firmware. HAProxy/Caddy/Gunicorn enrollment was tested separately by the
Docker integration suite. These results do not establish compatibility with
every public CA chain or every 6.49.x patch/model.

## Timestamp filename follow-up

The managed job now uses `<router>-YYYYMMDDHHIISS.rsc`, captured at script start
in the router's local timezone. All 29 unit tests passed again after this change.
Native RouterOS 6.49.19 execution also verified:

- 15 valid date/time inputs, covering all legacy month names, ISO dates, zero
  padding, year boundaries and leap days; 14 invalid inputs were rejected.
- Migration from a confirmed numbered export to a timestamped export.
- Invalid clocks, backward clocks, repeated seconds and local filename collisions
  preserve the previous confirmed file and persistent state.
- Pending timestamped exports and pending legacy numbered exports keep their
  filenames and contents across retry, even when the clock is invalid.

The job checks used real RouterOS file, export and state operations, with network
uploads and receipt responses stubbed. They do not repeat the earlier end-to-end
transport tests or establish native-v7 compatibility. Production data was untouched.

To render the standalone native clock fixture, run from the repository root:

```sh
python3 - <<'PY'
from pathlib import Path
fixture = Path("tests/routeros-timestamps.rsc.in").read_text()
helper = Path("mikrotik/timestamp.rsc").read_text()
Path("/tmp/mkbackup-timestamp-checks.rsc").write_text(
    fixture.replace("@TIMESTAMP_HELPER@", helper)
)
PY
```

Transfer that file through authenticated management access to a disposable router
and `/import file-name=mkbackup-timestamp-checks.rsc`. A successful run prints
`TIMESTAMP_CHECKS_PASSED`; the fixture does not change clock settings or backup jobs.

## Remaining production gates

Pilot representative physical v6 and v7 devices through the actual public
HAProxy endpoint, private Caddy backend, firewall and NAT. Verify the exact CA
chain, clock/DNS, v7 RSA
key import and selection, enforced SSH host verification, rejected mismatched
host keys, file persistence, two daily scheduled cycles and a restoration review.
No physical-router or native-v7 compatibility claim is made by repository tests.
Snapshot the archive, review `retention-preview`, and then explicitly enable
`RETENTION_ENABLED=1`; the default remains disabled.

## Admin enrollment validation

Additional unit coverage verifies encrypted credential storage, command disclosure
once per issuance, reissue/download races, idempotent submissions, concurrent UID
allocation, restart recovery, missing configuration acknowledgments, v6/v7 key
profiles, imported-account locks, CSRF and socket-role isolation. A real HAProxy
TLS integration test enrolls v6/v7 routers through the admin form, replaces an
unused token, rejects reissue after delivery, archives both transports' uploads,
and confirms receipt/checksum data. FTP and SFTP handles remain open throughout;
their bytes finish intact and listener/container identities remain unchanged.
