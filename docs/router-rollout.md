# RouterOS deployment and compatibility gate

This guide covers the manual SFTP workflow. For complete daily export installation
through HTTPS, including the explicitly selected RouterOS 6 plaintext FTP profile,
use [deployment.md](deployment.md). The SFTP capability requirements below still
apply to the automated v7 profile. Retain FTP ports while any v6 FTP profile remains.

This migration changes transport only. Keep each router's existing backup/export
generation, encryption choices and schedule until a separate restore test proves
the replacement. A binary `.backup` and text `.rsc` export serve different restore
purposes; upload both if the existing policy produces both. Do not add passwords
to the SFTP URL or command. Backup-file encryption passwords are a separate concern.

## Required evidence per firmware/model group

Complete `router-inventory.csv` and test one representative device per group:

1. Verify `/tool/fetch` has `sftp` upload support and the required file/manifest
   commands. Generated `upload.rsc` uses `/file/add type=file`, `/file/set contents`,
   `sftp-known-hosts-ignore=no`, functions and `:do ... on-error`. Confirm those
   commands on the installed release; do not import blindly into older firmware.
2. Verify private-key import accepts RSA 3072 PEM. Native OpenSSH private-key
   files are different; renaming one to `.pem` does not convert its format.
3. Confirm RSA-SHA2 authentication against the hardened server. `ssh-rsa` as a
   key type is fine; legacy SHA-1 `ssh-rsa` signatures are not. Do not enable weak
   algorithms for older routers; plan a separate firmware upgrade and repeat tests.
4. Verify `/ip/ssh known-hosts-validation` and `/ip/ssh/known-hosts` are supported
   and enabled. Pre-pin the server RSA key for its actual IP. Intentionally test
   a wrong key against a disposable test endpoint: unattended upload must fail.
   Do not set `sftp-known-hosts-ignore=yes` or exempt public subnets from validation.
5. Import the key for the exact user executing the scheduled job. Verify both
   local user ownership and any release-specific key-owner selection. Keep the
   remote server username equal to the enrolled router name. A manual upload as
   `admin` does not prove the scheduler can find its key.
6. Preserve a dedicated job identity and its required policies. Validate the
   minimal permissions needed for existing export/backup generation, local file
   operations and Fetch under the scheduler. Do not grant full administrator
   rights just to make an upload work. Administrator rights are needed to assign
   imported private keys to another user during provisioning.
7. Run the actual scheduler, reboot, and repeat. Upload a new filename each time,
   verify both the archived payload and receipt, and perform an isolated restore
   using the correct RouterOS/model constraints. Retain failed source files.

RouterOS 6 and untested/older RouterOS 7 releases remain **blocked** for direct
public SFTP until all requirements are met or an upgrade passes the pilot. The
[supported v6 workflow](routeros6.md) uses FTP; the former disabled SFTP lab
template has been removed.
The cited current manual describes newer RouterOS releases;
it does not prove that the same properties exist on installed older firmware.

## Provisioning procedure

1. Generate a unique key on a management workstation. Copy only its public key to
   the backup server and enroll the router; apply the registry before testing.
2. On the management workstation, verify the public bundle's server fingerprint
   through a separate trusted channel. Securely transfer the private PEM file
   directly to the router through existing verified management access.
3. Run the generated `enroll.rsc` as an administrator. It enables host verification,
   pins the RSA server key and imports/removes the uploaded private-key file.
   Inspect existing known-host entries before re-enrollment: do not silently
   remove or replace an unexpected pinned key. Use a version-specific manual
   procedure for intentional host-key rotation.
4. Import `upload.rsc` in the actual backup job owner's context. Global RouterOS
   functions are execution-context dependent. For reliable scheduled use, place
   the function definition and its call in the same job/script context, or import
   the function definition in that context before every call. Do not rely on a
   global function defined only in a previous interactive terminal session.
5. Call the function after existing backup generation with its local path and a
   unique remote basename. Preserve failed source backups for retry. The example
   does not create a schedule, change source generation, or delete source backups.
   On routers with a `flash` directory, persist backups across reboot under
   `flash/`; the root directory may be a volatile RAM disk. Monitor local free
   space and apply retention only after independent archival confirmation.

The generated retry loop reuses the same filename/content for up to three
attempts, sleeping five seconds between failures. If all attempts fail, it raises
an error and leaves the local backup and completion file. Retry those same bytes
later; use a new filename for a new backup. The collector cannot distinguish an
unintended duplicate name from an attempt to replace history, so it rejects
different content under an already archived name.

## Deployment stages and rollback

- Snapshot the existing volume; save the old deployment image/configuration and
  router scripts. Confirm physical volume names before starting a new service.
- Deploy SFTP on a separate TCP port alongside the existing backup workflow;
  do not remove the old job yet. Protect both endpoints during the transition.
- Pilot one device from each version/model group for **two scheduled cycles**,
  then verify an isolated restore. Record results in the inventory.
- Upgrade blocked firmware only in separately scheduled maintenance windows,
  with its own configuration backup and recovery method.
- Migrate compatible routers in small batches with schedule jitter to avoid a
  reconnect/backup burst. Watch router failures, authentication logs, last-success
  age, pending backlog, collector health, and free bytes/inodes on both volumes.
- After every router is validated, disable old upload jobs, close FTP control and
  passive ports, and retire vsftpd. Do not delete historical data or snapshots.
- Roll back by restoring the saved endpoint/job configuration for affected
  routers. Do not automatically fall back to plaintext transport, bypass host
  verification, or overwrite new archives. Keep incoming and archive volumes for
  diagnosis; old backups remain untouched outside the new `sftp/` subtree.

## Primary references

- [RouterOS SSH: private keys and host-key verification](https://manual.mikrotik.com/docs/management-tools/ssh/)
- [RouterOS private-key import formats](https://manual.mikrotik.com/docs/cli-reference/user/ssh-keys/private/import/)
- [RouterOS Fetch uploads](https://manual.mikrotik.com/docs/system-information-and-utilities/fetch/)
- [RouterOS files and persistent storage](https://manual.mikrotik.com/docs/system-information-and-utilities/files/)
