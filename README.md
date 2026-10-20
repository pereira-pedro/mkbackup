# mkbackup: MikroTik deployment and backups

Self-hosted backup enrollment, collection and browser administration for MikroTik
routers. Public repository: [pereira-pedro/mkbackup](https://github.com/pereira-pedro/mkbackup).
Licensed under [MIT](LICENSE). See [contributing](CONTRIBUTING.md) for
development and [security](SECURITY.md) for deployment boundaries and reporting.

## Quick start

Requires Docker with Compose v2, Python 3.9+ and OpenSSH/OpenSSL command-line tools.
For a fresh installation:

```sh
cp .env.example .env
chmod 600 .env
python3 scripts/manage.py init
# Edit .env: set your hostname and a unique ADMIN_PASSWORD (16+ characters).
docker compose --profile deployment --profile admin up -d --build --wait
```

The local console is at `http://localhost:15102/admin/` with default ports.
Production browsers and routers use HTTPS through your HAProxy; configure it
before issuing installers. For RouterOS 6, also enable `--profile legacy` and
configure FTP/NAT using [the deployment guide](docs/deployment.md). Defaults bind
only to loopback. All `mkbackup.example.com` endpoints are placeholders.

For layered configuration, use the same environment-file order in Compose and
the management CLI; later files override earlier ones:

```sh
docker compose --env-file .env --env-file secrets/local.env ps
python3 scripts/manage.py --env-file .env --env-file secrets/local.env deployment list
```

The optional local override is operator-created, Git-ignored configuration; it is
not needed for a fresh installation. Preserve your Compose project name when
upgrading so existing backup volumes remain attached.

To publish a copy on GitHub, use [the publication guide](docs/publication.md).
The original private history contains old credentials; export a clean source
snapshot before creating the public repository.

## Architecture

Install a daily text-export job through one HTTPS URL and a per-router, ten-minute
enrollment token. RouterOS 6.49.x uses plaintext FTP with unique credentials;
capable RouterOS 7 uses key-only SFTP with pinned server identity. A separate
collector seals completed uploads into private archive files. OpenSSH CA-signed
client certificates remain deferred.

```
router -- HTTPS :443 --> HAProxy -- HTTP :15102 --> Caddy --> enrollment
router -- SFTP :15100 --> sftp -- incoming-data --> collector --> ftp-data
router -- FTP :15101 --> ftp  --/                  no network    private archives
```

HAProxy manages the public certificate. Caddy listens only on HTTP port 15102,
bound to loopback by default; see [HAProxy setup](docs/deployment.md#haproxy).

Managed exports use `<router>-YYYYMMDDHHIISS.rsc` filenames, with minutes in `II`
and the router's local script-start time, for example `site6-20261020030509.rsc`.
Pending uploads keep their original filenames across retries and upgrades.

The collector writes the existing `ftp-data` volume; the optional admin reader
mounts it read-only. The internet-facing
FTP and SFTP services cannot access historical or retained backups. Pending uploads are
untrusted and can still be changed by their owner until archived. Once archived,
even an outstanding SFTP write handle cannot alter the retained inode.

Start with [the HTTPS deployment guide](docs/deployment.md) for server setup,
`deployment issue/list/revoke`, certificate trust, scheduled exports, recovery,
and server retention. The v6 FTP path is unencrypted; HTTPS protects provisioning
and receipt checks only. The sections below retain the manual SFTP workflow for
operators managing keys and backup generation separately.

The optional [administration console](docs/admin.md) at `/admin/` provides a
password login, router-name search, backup listings, individual downloads, and
**Enroll router / Reissue unused installer** with no routine upload-service restart.
Enable the `admin` Compose profile and configure `ADMIN_PASSWORD`; archive access
is read-only and isolated from enrollment and router upload accounts.

## 1. Inventory and preserve the existing deployment

This repository cannot discover or validate real routers without management
access. Fill in [the fleet inventory](docs/router-inventory.csv), using the
read-only [RouterOS inventory template](mikrotik/inventory.rsc). It deliberately
does not print script bodies, which may contain old passwords. Record firmware,
model, scheduler/job owner, backup size, source IP, and maintenance window.

Before deployment, snapshot the existing backup volume and retain the old image,
configuration and router schedules. Use the **same Compose project name** so
`ftp-data` resolves to the same physical volume. Inspect the rendered volume names
with `docker compose config --format json` and verify against `docker volume ls`.
Do not run `docker compose down -v` on production. Historical contents and their
permissions are left intact; only the archive volume's root directory becomes
root-owned `0755`, and new data is stored under `sftp/`.

## 2. Initialize server host keys

On the backup server:

```sh
cp .env.example .env   # only if .env does not already exist
python3 scripts/manage.py init
```

This creates persistent RSA 3072-bit and Ed25519 server keys plus an empty registry
inside `secrets/`. The helper never regenerates an existing host key. Protect and
back up this directory (directory `0700`, private keys/registry `0600`). Losing or
replacing host keys requires verified redistribution of the new host identity.
The image contains no host keys. An empty registry allows no router logins.

## 3. Generate and enroll a unique router key

For manual enrollment, on a **trusted management workstation**, not the backup server:

```sh
python3 scripts/manage.py keygen router1 --output-dir ./secrets/enrollment/router1
```

The private file `router1.pem` is RSA 3072 in PKCS#1 PEM format, suitable for
unattended RouterOS import. It has no passphrase: protect it as a credential.
Deliver it directly to that router over existing authenticated SSH/WinBox access;
do not put it in Git, an image, or the backup server. Transfer only its `.pub`
file to the backup server's `secrets/public-keys/router1.pub`, then enroll there:

```sh
# Start the stack first (section 4), then stage/apply this identity online.
python3 scripts/manage.py enroll router1 --public-key ./secrets/public-keys/router1.pub
python3 scripts/manage.py apply
python3 scripts/manage.py bundle router1 --host 203.0.113.10 --port 15100 \
  --job-owner backupagent --output ./secrets/bundles/router1
```

Replace the example address and `backupagent` with the real server IPv4 address
and actual RouterOS scheduler owner. Bundle generation writes public host-key
pinning/import instructions and an upload function, **not** the private router
key. Compare the server fingerprint over an independent trusted management path
before importing. Do not bootstrap trust with an unchecked network key scan.

Each router gets a stable UID/GID starting at 10000. Existing UIDs cannot be
changed through the helper; disabled entries remain reserved. Reusing the same
public key on another router is rejected. `enroll` on an existing router overlaps
another key for rotation. Optional settings:

```sh
python3 scripts/manage.py enroll router1 --public-key ./secrets/public-keys/router1.pub \
  --max-bytes 104857600 --expected-interval-seconds 86400
```

The default maximum payload is 100 MiB. The interval is for monitoring, not a
server-side backup scheduler. Keep private enrollment bundles on the workstation
only as long as needed under your credential-management policy.

## 4. Build and start locally, then gate public exposure

```sh
docker compose config --quiet
docker compose build --pull
docker compose up -d --wait --wait-timeout 60
docker compose logs -f sftp collector
```

`SFTP_BIND_ADDRESS` defaults to `127.0.0.1`, and `SFTP_PORT` defaults to `15100`.
The service listens on container port 2222. For internet access, explicitly bind
the appropriate host interface (or `0.0.0.0` where required by cloud NAT), and
allow just that TCP port through the edge firewall/security group and Docker-aware
host firewall. Do not assume ordinary host UFW rules alone restrict Docker ports.
Allow known router source addresses when stable; monitor authentication load for
dynamic sources. Keep FTP control/passive-port rules only while v6 FTP is in use.

**Before public rollout**, provision host-enforced byte and inode quotas for the
incoming storage, a capacity-limited archive filesystem, and free-space alerts.
The default Compose local volumes do not impose portable disk quotas. The
collector rejects oversized payloads, but an authenticated account could still
fill incoming storage before collection. Archive retention is opt-in via
`RETENTION_ENABLED=1`, after a snapshot and `manage.py retention-preview`: keep
the seven newest files plus the first success in each of twelve UTC calendar
months. It applies only to receipt-backed data in the managed archive namespace.
Retention/restore operations require independent administrator access, and
off-host snapshots or immutable copies are still needed against administrator
or container-host compromise. Keep CPU/memory/PID limits and rotated logs enabled.

Secrets are read-only runtime mounts; generated account databases and copied
host keys live on bounded tmpfs. `.dockerignore` admits only runtime source and
public configuration, excluding `.git`, `.env`, router keys, bundles and tests.
Rebuild with `--pull` regularly for Ubuntu/OpenSSH updates. The image rebuilds
Ubuntu’s vsftpd source package with [two narrow seccomp fixes](patches/vsftpd-seccomp.patch);
compiler dependencies remain in a separate build stage. Keep the source patch
reviewed as Ubuntu updates the package.

## 5. RouterOS rollout: capability-gated, never weaken SSH

Follow [the router rollout guide](docs/router-rollout.md). The generated scripts
target RouterOS 7 releases that actually expose the required features; neither
an arbitrary RouterOS 7 release nor RouterOS 6 is assumed compatible. Routers
without RSA-SHA2, private-key import, or enforced SFTP host-key verification are
blocked pending a tested firmware upgrade. Legacy SHA-1 `ssh-rsa` signatures are
not enabled on the server. RSA keys with SHA-2 signatures are supported.

For **RouterOS 6.49.x**, use the [FTP deployment installer](docs/deployment.md)
on port 15101. The former disabled v6 SFTP lab template has been removed; manual `bundle`
provisioning supports only capable v7 SFTP clients. SFTP port 15100
maps to container port 2222 and does not change the default loopback bind.

Run `enroll.rsc` as an administrator after securely transferring `router1.pem`.
Import `upload.rsc` under the actual backup scheduler owner. The key must belong
to that execution context; an interactive administrator upload is insufficient.
Preserve existing backup generation, encryption and schedules. After creating a
backup, call the generated function with a local file and a new unique basename:

```routeros
:global mkbackupUpload
$mkbackupUpload "flash/site.backup" "router1-20261020-010000-unique.backup"
```

Use a unique name for every new backup, including a nonce/counter in addition to
date/time. Reuse the same name only when retrying the **same bytes**. The function
uploads the payload, then its completion manifest, retries failures up to three
times, and logs "uploaded", not "archived". It never deletes the source backup.
Keep failed files for retry and alert on router storage usage. On routers with a
RAM-backed root directory, store backups requiring reboot persistence in `flash/`
or other persistent storage; see the rollout guide. Use independent archival
monitoring to confirm server-side completion before applying local retention.

## Completion and archive contract

One flat payload `/upload/<filename>` is followed by
`/upload/<filename>.done.json`, UTF-8 JSON with exactly:

```json
{"version": 1, "filename": "router1-unique.backup", "size": 12345}
```

Filename: 1-128 ASCII letters/digits/dots/underscores/hyphens, starting with an
alphanumeric character; paths and the reserved `.done.json` payload suffix are
rejected. Size is a positive integer at or below that account's `max_bytes`.
The registry (not manifest data) determines router identity and archive location.
Extra/duplicate JSON fields, symlinks, hardlinks, FIFOs and other non-regular files
are rejected. Directory creation, downloads, links, renames and deletion are
blocked by SFTP. Metadata operations needed by clients are allowed on pending
files only. SFTP offers no router read access to retained data.

The collector uses no-follow descriptor opens and compares source identity,
size, mtime and ctime before/after streaming into a new file. It calculates SHA-256,
fsyncs, and exclusively publishes that new inode; it never moves a writable upload
inode or replaces an existing archive. It then publishes a private receipt and
persists status before cleaning up unchanged incoming files. A retry of the same
filename/content is idempotent; different content is rejected and retained for
investigation. Interrupted payloads/manifests stay pending. There is no unattended
cleanup of rejected/stale uploads: monitor backlog and clean them administratively.

New paths inside the **collector only**:

- `/archive/sftp/<router>/<filename>`: root-owned `0400` payload.
- `/archive/sftp/<router>/.receipts/<filename>.json`: SHA-256, byte count, router,
  filename and server UTC archival timestamp; `0400`.
- `/archive/sftp/<router>/.last-success.json`: durable monitoring summary.

Only a payload with a receipt counts as a completed archive. A crash after payload
publication and before its receipt is recovered on retry without replacing the
retained inode. Copy/fsync/storage failures never report a successful archive.
The collector is a single service with no network interface or published ports.
On restart it removes only its precisely named, collector-owned staging files
inside the new archive subtree; completed payloads and receipts are preserved.

## Monitoring, rotation and revocation

```sh
docker compose exec -T collector python3 /usr/local/lib/mkbackup/status.py
docker compose logs --since 1h collector
```

Status JSON includes heartbeat, health, pending payload count/bytes, completion
count, scan truncation, last error and durable last-success receipt per router,
plus filesystem available bytes/inodes (these do not replace quota monitoring).
Counts are sampled at the start of a cycle and settle on the next cycle. A router
is overdue after 1.5 times its expected interval, or until its first archive.
Alert on overdue backups, any archive rejection, a truncated scan, growing backlog,
storage errors, unhealthy containers or a heartbeat older than 300 seconds.
Scans are bounded at 10,000 directory entries per router per cycle; inode quotas
and operational cleanup must prevent one account monopolizing the scanner.

Rotate by enrolling a new public key, running `python3 scripts/manage.py apply`,
importing the replacement private key on that router and verifying a scheduled
archive using the **new key's accepted fingerprint in SFTP authentication logs**,
then revoking the old key. A successful upload while both keys are allowed does
not by itself prove which key RouterOS selected:

```sh
python3 scripts/manage.py revoke-key router1 --fingerprint SHA256:OLD_FINGERPRINT
# Or disable the entire router account:
python3 scripts/manage.py disable router1
```

By default revocation/disable recreates SFTP, collector, and any configured FTP service with the changed registry
and waits for health. This intentionally disconnects **all** active SFTP sessions,
including other routers, because removing an authorized key cannot terminate an
already authenticated session. Recreate during a maintenance window; failed jobs
retry. Live-apply failure is reported explicitly: fix Compose and re-run `apply`.
`--stage-only` changes configuration only and explicitly does **not** revoke live
sessions. For custom Compose projects/overrides, use staging then recreate both
services with that deployment's actual Compose invocation and verify health.
The provisioner database is the live registry. `--secrets-dir` selects bootstrap
files and local key material, not a separate live registry. Use `--offline` only
to stage seed accounts before the first deployment. Online CLI mutations all
use the selected Compose project’s provisioning service.

Use `deployment revoke NAME` to also invalidate HTTPS enrollment/status tokens.
For publication and the legacy credential-history migration, follow
[the publication guide](docs/publication.md).

## Verification

```sh
docker compose config --quiet
docker build --pull -t mkbackup-sftp-test:local .
docker run --rm --network none --read-only --tmpfs /tmp:rw,size=256m \
  --entrypoint python3 -v "$PWD:/workspace:ro" -w /workspace \
  mkbackup-sftp-test:local -m unittest discover -s tests -p 'test_*.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 tests/integration.py
```

Tests require Python 3.9+, the OpenSSH client/keygen tools, and Docker Compose.
The unit image includes cryptography; run the complete unit suite in that image.
A host-only run needs compatible cryptography installed separately. The integration suite uses temporary keys,
a local test certificate, HAProxy terminating TLS in front of Caddy's HTTP
backend, and an isolated Compose project/volumes,
then removes those test resources. It exercises actual SFTP operations and a
held-open write handle, authentication rejection, user isolation, forwarding/shell
denial, host-key pinning, recreation, rotation and live-session revocation.
It also verifies FTP restrictions/open handles, HTTPS token replay rejection,
both generated credential profiles, unprivileged enrollment workers, and admin
login/search/download/logout through the same HTTPS edge. Admin checks cover
session restart invalidation, source-IP login throttling, archive isolation and
100 MiB streaming with bounded memory. Unit
tests cover encrypted enrollment/concurrent redemption, calendar retention,
malicious manifests, filesystem tricks, concurrent mutation, partial copies,
disk-full errors and recovery. No live MikroTik compatibility or
restore claim is made until the required hardware pilot is completed.

Recorded test coverage and RouterOS 6.49.19 emulator results are in
[the validation report](docs/validation.md).
