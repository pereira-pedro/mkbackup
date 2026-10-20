# RouterOS 6.49.x deployment

The supported v6 workflow uses a unique FTP account, a daily redacted text export,
and a completion manifest. Installers and receipt confirmations use authenticated
HTTPS through HAProxy. See [deployment.md](deployment.md) for complete setup and
[validation.md](validation.md) for the firmware versions actually tested.

```sh
python3 scripts/manage.py deployment issue site6 --routeros-major 6 \
  --host 203.0.113.10 --port 15101 --job-owner admin
```

Set the actual server address, published FTP control port and installing account.
The default passive range is 15110–15119. Configure its public IPv4/NAT and firewall
rules together; the port alone is insufficient for FTP data connections.

The operator downloads the private installer once with certificate validation,
then imports it. A correct clock and trusted CA chain are required. Do not disable
HTTPS certificate validation to make enrollment work. The job uses `/export
hide-sensitive`, preserves unresolved exports for retry, and enables the daily
scheduler only after the collector confirms the first archive.

FTP exposes both credentials and backup contents to network observers and permits
in-transit modification. The collector protects retained archive inodes, but
cannot establish the authenticity of plaintext FTP bytes. Use the v6 profile only
where that risk is accepted; prefer a compatible v7 SFTP migration.

## SFTP compatibility

RouterOS 6 does not have a supported direct-SFTP profile in this project. The old
disabled SFTP lab template and its bundle option have been removed. Use
`deployment issue --routeros-major 6` for FTP; `bundle --routeros-major 7` is for
manual, capability-tested SFTP only.

Do not enable legacy SHA-1 SSH signatures, passwords, or skipped server identity
checks on the shared SFTP listener. Plan firmware upgrades separately and complete
[the SFTP capability pilot](router-rollout.md) before migration. Repository tests
are not evidence that every 6.49.x hardware model or every public CA chain works.
