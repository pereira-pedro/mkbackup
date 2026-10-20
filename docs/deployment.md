# Install from one HTTPS URL

RouterOS 6.49.x uses **plaintext FTP** on TCP 15101, with passive TCP ports
15110–15119. Compatible RouterOS 7 uses key-only **SFTP** on TCP 15100.
Both obtain their personalized installer from `https://mkbackup.example.com/`.
The hostname and ports are configurable. No live DNS, server or router is changed
by adding these files to the repository.

For password-protected router search, listings and downloads, enable the optional
[administration console](admin.md). It uses `/admin/` on the same HTTPS origin
and does not give enrollment or router accounts access to retained payloads.

The request path is **internet HTTPS :443 → HAProxy → HTTP :15102 Caddy →
enrollment**. HAProxy owns the public certificate and its renewal. Use TLS 1.2/1.3
and a certificate chain verified with the legacy routers; an RSA leaf certificate
maximizes compatibility. Caddy's image is pinned by version and digest; update
the pin when applying future security releases. Caddy performs no ACME requests
or HTTPS redirects and needs no persistent certificate storage.
The listener uses [Caddy's explicit HTTP configuration](https://caddyserver.com/docs/caddyfile/options#auto-https).

The v6 choice exposes FTP credentials and exports to network observers and permits
on-path modification. HTTPS enrollment does not protect FTP transfers. Each
router has a separate account; FTP has no access to retained archives. Prefer
source-IP restrictions where stable. FTPS and automatic firmware upgrades are not
part of this deployment.

## Server setup

Preserve the existing Compose project name and snapshot its `ftp-data` volume.
Keep that snapshot and previous configuration until restoration has been tested.
Never use `docker compose down -v` on production.

```sh
cp .env.example .env  # only if no .env exists
python3 scripts/manage.py init
docker compose build --pull
```

`init` preserves existing host keys and registry, and adds missing
`ftp_passwords.json` and the 32-byte `enrollment.key` under `secrets/`. Back up
these protected files. They contain password hashes and the key for temporary
installer encryption; no private router keys are retained after delivery/expiry.
The encrypted enrollment database is in the `enrollment-data` Docker volume.

Set DNS A records for `DEPLOYMENT_HOST` to HAProxy's public address. Publish an
AAAA record only when IPv6 routing and firewalling work. Configure public HTTPS
and certificate renewal on HAProxy. Set in `.env` (same-host HAProxy):

```dotenv
DEPLOYMENT_HOST=mkbackup.example.com
CADDY_BIND_ADDRESS=127.0.0.1
CADDY_PORT=15102
SFTP_BIND_ADDRESS=0.0.0.0
SFTP_PORT=15100
FTP_BIND_ADDRESS=0.0.0.0
FTP_PORT=15101
FTP_PUBLIC_ADDRESS=203.0.113.10
FTP_PASSIVE_MIN=15110
FTP_PASSIVE_MAX=15119
```

Replace the example public FTP IPv4; NAT must forward the configured passive
range unchanged. Open the same ports in the edge firewall and Docker-aware host
firewall. Keep the example's loopback bindings for development. Provision
host-enforced incoming byte/inode quotas and storage alerts before public use.

### HAProxy

Merge [the HAProxy example](haproxy.cfg.example) into your existing configuration.
Route the deployment hostname to `127.0.0.1:15102` over **HTTP**, preserving the
original `Host` and `Authorization` headers. The health check uses `/healthz`
with `Host: mkbackup.example.com`; update both hostnames if configuring another
`DEPLOYMENT_HOST`. Set `X-Forwarded-Proto: https`, avoid retries of redeemed
enrollment requests, disable caching, and never capture Authorization headers
or response bodies in logs. Validate your merged configuration with
`haproxy -c -f /etc/haproxy/haproxy.cfg` before reloading it.

If HAProxy runs on another host, set `CADDY_BIND_ADDRESS` to the Caddy host's
private address and use that address in HAProxy's backend. Permit TCP 15102 only
from HAProxy in the edge and Docker-aware host firewall. This hop carries tokens
and installers in plaintext, so it must stay on a trusted private network.
For containerized HAProxy, loopback refers to its own container: use a shared
private Docker network or a reachable private host address. No HAProxy service
is added to Compose because this deployment uses your existing proxy.

Caddy's Compose service retains the name `https` for compatibility, but publishes
only HTTP port 15102 and runs as UID 10001. The upstream binary's file capability
requires `NET_BIND_SERVICE` in the bounding set even with this high-port listener;
all other capabilities are dropped and privilege escalation is disabled.
Remove obsolete `HTTPS_BIND_ADDRESS`, `HTTPS_PORT` and `HTTP_PORT` settings from
existing `.env` files and replace them with `CADDY_BIND_ADDRESS`/`CADDY_PORT`.
Previously created `caddy-data`/`caddy-config` volumes are left untouched and are
no longer mounted. Keep public installer and receipt URLs on `https://`; the
RouterOS trust checks validate HAProxy's certificate, not the internal HTTP hop.

Check the backend locally with the configured hostname:

```sh
curl --fail -H 'Host: mkbackup.example.com' http://127.0.0.1:15102/healthz
```

After the services below are running, this should return `ok` with no redirect.
Also check `https://mkbackup.example.com/healthz` through HAProxy before issuing
installers. Public HTTP-to-HTTPS redirects, if desired, belong on HAProxy.

```sh
docker compose --profile deployment --profile legacy config --quiet
docker compose --profile deployment --profile legacy up -d --wait
python3 scripts/manage.py retention-preview
```

After reviewing the preview and verifying the archive snapshot, set
`RETENTION_ENABLED=1` and recreate the collector. Retention then runs after every
successfully archived payload and on idle cycles to recover interrupted pruning.
It is off by default so upgrading a configuration cannot silently delete data.

The collector mounts `ftp-data` read-write; the optional archive reader mounts
it read-only. FTP/SFTP receive incoming storage and read-only configuration
snapshots. The public enrollment gateway mounts only its delivery socket and
receipt index; it has no database, encryption key, registry or payload access.
The provisioning service owns enrollment storage and keys, drops to UID/GID 10001
after bootstrap, and has no network, Docker socket or backup-payload mount.

## Upgrade to live provisioning

Back up `secrets/`, the `enrollment-data` volume and existing archives first. Run
`python3 scripts/manage.py init` to add any missing public host-key file without
regenerating host keys. Deploy the updated stack once with the existing Compose
project and volumes. This initial rollout recreates services; schedule it normally.

On first startup, the provisioner imports existing router identities/password
hashes, marks imported routers ineligible for browser reissue, and preserves the
enrollment encryption key/database. Subsequent restarts use its durable database;
`secrets/routers.json` and `ftp_passwords.json` become bootstrap inputs, not the
live registry. Back up `enrollment-data`, which now also holds identities and jobs.
Do not edit seed files to change live accounts. All online CLI mutations use the
same provisioning service. `--offline` is only for preparing seed entries before
the first deployment. Never use it as a fallback when a live control service fails.

Configuration snapshots are derived and can be recreated from the database.
Restore the database/key and service configuration together for rollback; preserve
a pre-upgrade image and volume snapshot until the rollout is verified. No archive
migration or automatic retention activation occurs.

## Issue an installer

The [admin console](admin.md#enroll-a-router) provides the normal enrollment flow.
The CLI remains available on the server for the account that will import the script:

```sh
python3 scripts/manage.py deployment issue site6 --routeros-major 6 \
  --host 203.0.113.10 --job-owner admin
python3 scripts/manage.py deployment issue site7 --routeros-major 7 \
  --host 203.0.113.10 --job-owner admin
```

Use a distinct router name per device. `--host` is the FTP/SFTP server IPv4;
`--base-url`, if supplied, must match the configured HTTPS origin; `--port` overrides the transport port and
must match the published port. Configure the same `--job-owner` that will import
and own the scheduled job. Names are restricted to safe account identifiers.

Issuance queues a serialized provisioning job, generates unique credentials,
live-refreshes the relevant transport and collector, then issues the token.
Existing uploads are not disconnected. Timeout or partial failure produces no
usable token; check the enrollment status and reissue an unused installer.
Existing accounts require `--replace` for deliberate CLI recovery/rotation; UIDs
never change. Replacing FTP immediately rotates its password. SFTP replacement
overlaps keys; verify the new fingerprint before revoking a superseded key.

The CLI prints **private** instructions containing a one-download, 10-minute
token. Deliver those instructions through an authenticated management channel.
Do not put them in tickets, shared logs, URLs, or shell tracing. Router commands:

```routeros
/tool fetch url="https://mkbackup.example.com/" check-certificate=yes http-header-field="Authorization: Bearer <TOKEN>" dst-path=mkbackup-install.rsc
/import file-name=mkbackup-install.rsc
```

The token chooses v6/v7 automatically. Explicit `/routeros6.rsc` and
`/routeros7.rsc` URLs enforce the token's profile. Tokens are stored hashed and
consumed before returning bytes; interrupted downloads need a replacement token.
Expired ciphertext is purged by requests and 30-second health checks. No HTTP
access log is enabled. The returned script contains credentials: import promptly
under the specified administrator and do not share it. Successful or handled
failed execution removes `mkbackup-install.rsc` and temporary PEM files. If import
cannot parse or is interrupted, manually remove those credential-bearing files.

For another Compose project, supply global options **before** `deployment`:
`--project-name NAME --env-file /path/.env --compose-file /path/docker-compose.yml`.
Repeat `--compose-file` for overrides. Use the same options for issue/list/revoke,
apply and retention-preview; test environments must never target production.

## HTTPS trust prerequisites

On a router, verify DNS, correct date/time and the CA trust chain before fetching.
If the relevant public root is absent, download that root from the CA's official
site on a trusted workstation, verify its fingerprint through a trusted channel,
and transfer it through authenticated WinBox/management access. Import it with
`/certificate import file-name=trusted-root.crt`, inspect the imported certificate,
and mark the verified CA trusted. Retry Fetch with `check-certificate=yes`.
Never download a trust anchor through an unverified connection to fix trust.
Test expired/wrong-name/untrusted server certificates on the exact firmware;
do not ship a device profile whose HTTPS identity checks fail that pilot.

## Job behavior and recovery

The installer owns exactly `mkbackup-export`, `mkbackup-state`, and
`mkbackup-daily`. It refuses conflicting names/owners and preserves unrelated
jobs. Managed reinstallation keeps the persistent filename state and unresolved
export.
The scheduler runs daily between 03:00 and 03:30, using a stable router-specific
minute offset and the router's current timezone. The installer does not change
timezone, clock synchronization, incoming login policies or firmware.

New files are named `<enrolled-router-name>-YYYYMMDDHHIISS.rsc`, for example
`site6-20261020030509.rsc`. The timestamp is captured when the script starts,
using the router's existing local timezone: year, month, day, hour, minute (`II`),
second. Both legacy RouterOS 6 dates and RouterOS 7 ISO dates are accepted.
The clock must have a valid date from year 2000 onward. A repeated timestamp or
backward clock adjustment stops new generation before deleting the previous local
export; retry after the clock advances beyond the last used timestamp. The job
does not change clock synchronization or timezone settings.

The job uses native sensitive-value omission (`hide-sensitive` on v6; the default
on capable v7), exports text only, then uploads the payload and a byte-count
completion manifest. Runtime FTP/status credentials are in
`flash/mkbackup-credentials.txt` where `flash/` exists, otherwise in the file
root. They are absent from the job source and configuration export. Protect
router management/file access: this runtime credential file must remain for
reboots. Native export redaction does not scrub secrets manually embedded in
other pre-existing script sources; review those before deploying exports.

The job has three transfer attempts, five-second delays, and up to 30 seconds
of HTTPS archival polling. Its status token can only read that router's receipt
metadata and cannot enroll routers or download backup contents. After confirmation
one local export remains. At the next run it removes that confirmed local export
before generating the next. Pending exports are retained and retried unchanged;
new exports wait for their confirmation. Temporary completion files are removed.
An upgrade also retries unresolved exports with their original numbered filenames
before generating timestamped exports. Existing server archives are not renamed.
Already installed routers need a newly issued/imported installer to update the
job; there are no automatic remote script updates.

Persistent state is in the managed state object's comment, not a volatile global.
An interrupted export generation is marked `generating` and is never uploaded as
complete automatically. Inspect the local file and server status before recovery.
If discarding an incomplete generation, remove only that managed local file and
set the state comment to `mkbackup-managed:v1:ROUTER|LAST_STAMP||confirmed`, retaining
the existing timestamp (or legacy counter during upgrade) so filenames cannot be
reused. Do not reset that value or mark an unresolved upload confirmed. Missing
pending files also require inspection;
test `flash/`/root persistence after reboot for each hardware group.

The scheduler stays disabled if the initial run fails. After fixing the cause:

```routeros
/system script run mkbackup-export
```

Only after that command confirms archival:

```routeros
/system scheduler enable [find where name="mkbackup-daily"]
```

V7 requires enforced known-host validation and RSA-SHA2. A mismatching pin is
rejected rather than replaced; unsupported features stop installation. Monitor
pending/export age, storage, collector health, token state and authentication
failures. Neither successful file upload nor a completed installer download alone
proves a successful backup. Old jobs are not disabled automatically.

## Retention, revocation and rollout

The collector keeps the union of seven newest archives and the first successful
archive in each of the current and previous eleven UTC calendar months, per
router. Original receipt timestamps survive retries. Missing months do not extend
the window. The maximum is 19 copies, often fewer due to overlap. Server retention
does not mean seven days; it counts seven successful files. Pruning only examines
receipt-backed data inside `/archive/sftp/<router>` (the historical namespace
name is retained for both transports). Unmanaged/historical data is not pruned.
Durable deletion intents allow restart recovery; errors are logged and retried.

```sh
python3 scripts/manage.py deployment list
python3 scripts/manage.py deployment revoke site6
docker compose logs --since 1h collector
docker compose exec -T collector python3 /usr/local/lib/mkbackup/status.py
```

Deployment revocation invalidates enrollment/status tokens, disables the account,
and recreates transport services to terminate existing sessions. Other sessions
are disconnected too. Failed live revocation is reported explicitly. Do not
expect revocation to remove a previously imported private key from a router;
remove superseded keys there through authenticated management access.

Pilot one real router from every firmware/model group for two scheduled cycles.
Verify v6 passive FTP through actual NAT, v7 wrong-host-key rejection, HTTPS
identity checks, scheduler owner/key selection, credential omission from exported
job source, local persistence/one-file behavior, server retention and a restoration
review. Text exports omit sensitive values and cannot fully reconstruct secrets.
Record results in `router-inventory.csv` before batch rollout. Automated repository
tests cannot substitute for these physical-router and network checks.

See [validation.md](validation.md) for recorded automated and RouterOS 6.49.19
emulator results and the remaining physical-router/public-endpoint gates.
