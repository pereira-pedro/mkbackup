# Security policy

Report vulnerabilities privately through the repository's **Security → Advisories
→ Report a vulnerability** page. Maintainers must enable private vulnerability
reporting when creating the GitHub repository. If that option is unavailable,
contact a maintainer privately through their GitHub profile before sharing details.
Do not post credentials, tokens, router exports or private keys in public issues.

This project has no released version or guaranteed response-time policy yet.
Reports should identify the commit, affected service and a minimal reproduction
using synthetic data. The current branch is the supported development target.

## Deployment boundaries

- RouterOS 6 uses explicitly unencrypted FTP. HTTPS enrollment does not protect
  FTP credentials or exports from observation/modification in transit.
- Public HTTPS terminates at the operator's HAProxy. Restrict its HTTP Caddy hop
  to a trusted network and configure the supplied login throttling rules.
- Per-router accounts can modify pending uploads. Only collector-confirmed
  archives are retained backups; keep independent off-host copies.
- Set host storage/inode quotas and capacity alerts. Container memory limits and
  the collector's payload limit cannot bound arbitrary pending uploads.
- Root on the Docker host can inspect secrets and backups. Never publish `.env`,
  `secrets/`, archive volumes, raw scan reports or production inventory data.

Read [the deployment guide](docs/deployment.md) and
[the validation limits](docs/validation.md) before internet exposure.
