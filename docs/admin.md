# Browse and download backups

The optional console is at **https://mkbackup.example.com/admin/**. It provides
one shared administrator login, router-name search, paginated backup listings,
individual downloads, and authenticated router enrollment. File previews, deletion,
bulk downloads and browser-based credential rotation/revocation remain outside this version.

## Enable the console

Generate a unique password privately:

```sh
openssl rand -base64 32
```

Set `ADMIN_PASSWORD` in the existing, Git-ignored `.env` file. Use at least 16
characters and at most 1024 UTF-8 bytes; no default password exists. Single-quote
the `.env` value if it contains `$` so Compose does not interpolate it. Protect
`.env` with mode `0600`. Only the admin service receives this variable; Docker
administrators can inspect container environment values.

Merge the login-throttling rules and `admin_login_limits` table from
[the HAProxy example](haproxy.cfg.example) into the existing HTTPS frontend. Keep
the deployment-host condition. The rules allow ten login POSTs per source IP in
a rolling minute, counting both successful and failed submissions. They use the
actual connection source, not `X-Forwarded-For`. Avoid capturing passwords,
cookies, request bodies or responses in proxy logs. Validate and reload HAProxy
using your existing operational procedure.
The example uses stick-counter slot 0; if that slot is already used by the
frontend, select a free slot and update both `track-sc0` and
`sc_http_req_rate(0)` together. The source-address string table covers IPv4 and
IPv6. See the [HAProxy stick-table reference](https://docs.haproxy.org/3.2/configuration.html#11.1).

Build and start with the existing Compose project name and environment:

```sh
docker compose --profile deployment --profile legacy --profile admin config --quiet
docker compose build
docker compose --profile deployment --profile legacy --profile admin up -d --wait
```

Omit `--profile legacy` only when FTP is not in use. Preserve the existing project
name so the original archive volume is reused. No archive migration, permission
change, new public port or HAProxy TLS change is needed. Caddy still receives
private HTTP on port 15102 and preserves `/admin/` when forwarding to the console.
If the admin profile is off, the admin route is unavailable; enrollment and receipt
routes continue operating.

Keep port 15102 restricted to HAProxy. The login and session cookie traverse that
HTTP hop, so it must remain on the trusted network described in
[deployment.md](deployment.md#haproxy). Browsers must use the public HTTPS URL;
the console's secure cookies require HTTPS for non-loopback hostnames. Caddy also
accepts `localhost` and `127.0.0.1`; opening `/` on those names redirects to the
admin console. Modern browsers provide a [localhost exception for secure cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#secure);
automated HTTP clients may still require explicit cookie handling. Production
access should continue through HAProxy's HTTPS origin.

## Enroll a router

Open **Enroll routers → Enroll router** after signing in. Choose the RouterOS
profile before filling the form so its port is prefilled correctly. Enter the
stable enrollment name, router-reachable server IPv4, published transport port,
and installing RouterOS account. Addresses/ports can be overridden per router;
they must reach this instance and do not configure NAT, listeners or firewalls.
The HTTPS download origin stays centrally configured by `DEPLOYMENT_HOST`, with
an optional `ENROLLMENT_BASE_URL` override for a nonstandard HTTPS port.

RouterOS 6.49.x receives unique plaintext FTP credentials. Compatible RouterOS 7
receives an RSA 3072 PEM key and pinned server identity. No capabilities are assumed
for an arbitrary v7 release: complete the existing firmware pilot before rollout.

Submit **Prepare installer**, then use **Refresh status** until the job is ready.
Only after the transport and collector acknowledge its configuration can you POST
**Show installation commands once**. Paste both commands into the configured
RouterOS account. Tokens are single-use and expire ten minutes after issuance,
including time before commands are shown. A ready installer is not a completed
backup: verify the first archive separately. Routine issuance leaves existing
uploads and listeners running.

**Reissue unused installer** invalidates old instructions and generates replacement
credentials without changing the stable UID. It is available only before any
installer for that router has been downloaded, including after token expiration.
A dropped installer download still counts as delivery. After delivery, or for
routers imported during migration, use deliberate CLI recovery/rotation; the UI
cannot replace credentials on an installed router. Jobs and command disclosure
are bound to the submitting browser session. After logout/session expiration,
unused installers can be reissued from a new session once any active job finishes.

Control calls use separate internal Unix sockets. The public HTTP enrollment
service cannot create accounts or invoke CLI operations. The provisioning service
owns the encrypted SQLite state, writes versioned registry/password snapshots,
and has no Docker socket or backup-payload mount. Only FTP receives password-hash
snapshots. Upload services refresh their own root-owned chroots and tmpfs NSS
files, while the collector reloads validated registry generations between cycles.
Failures issue no usable token and leave a failed job eligible for safe recovery.

## Search and download

Sign in with the configured password; no username is required. Search by the
stable **enrollment name**, using any case or substring. Changing RouterOS
`/system identity` does not rename the enrollment name or its archive directory.

The router table shows available-file counts and the latest successful archive
time. Open a router to see filename, server archival time in UTC, size, SHA-256,
and a Download button. Both tables use pages of 50 entries. Newest backups appear
first according to their original server receipts, not the router's clock.

Both old numbered files and new `YYYYMMDDHHIISS` filenames are supported. Empty
managed router directories and retained archives belonging to disabled routers
remain visible. Pending uploads, metadata files and historical files outside
`/archive/sftp/<router>` are excluded. Use the existing Docker/SSH administrative
tools to retrieve historical data outside this managed namespace.

Each download is authenticated and checked against its receipt before any
payload is returned. A file removed by retention before opening returns 404;
an already-open download can finish during pruning. An integrity mismatch blocks
the download and reports an error. Listings identify a router with invalid
archive metadata as unavailable rather than presenting a misleading empty list.

## Sessions, rotation and isolation

Sessions expire after 30 minutes idle or eight hours total. Sign out invalidates
the session immediately. Login/logout use CSRF protection; cookies are host-only,
scoped to `/admin/`, and have `Secure`, `HttpOnly` and `SameSite=Strict`. Responses
are not cached. Session token hashes and CSRF hashes are stored in a bounded,
private SQLite database on tmpfs shared by the web workers. Passwords, plaintext
session tokens and backup contents are not logged.

After changing `.env`, rotate the password by recreating the admin container:

```sh
docker compose --profile admin up -d --no-deps --force-recreate --wait admin
```

Every restart/recreation discards all sessions, including during password
rotation. The new password is validated before workers start; missing or invalid
configuration fails closed. With one shared account, logs cannot attribute
downloads to individual people. Structured logs record login outcomes, logout,
and download starts:

```sh
docker compose --profile admin logs --since 1h admin
```

The web service runs as UID/GID 10001 without capabilities. It mounts only the
reader and admin-provisioning socket volumes read-only and temporary session storage; it cannot directly
access archives, incoming files, router credentials, enrollment storage or Docker.
The internal reader runs as UID 0/GID 10001 so it can read existing root-owned
`0400` files, with all capabilities dropped, no network, and read-only archive and
root filesystems. Its Unix socket allows only managed listing/download operations.
Archive ownership and modes stay unchanged, and the existing enrollment service
still has no access to backup contents.

Health checks cover the admin HTTP service and its reader socket. A reader failure
makes archive requests unavailable; the application does not fall back to unsafe
paths or publish unverified files. Downloads stream in 64 KiB chunks with bounded
concurrency, including the default maximum 100 MiB payload.

## Disable the console

```sh
docker compose --profile admin stop admin archive-reader
```

This stops console access without touching backups, retention, enrollment or
router jobs. Do not use `docker compose down -v` on production.
