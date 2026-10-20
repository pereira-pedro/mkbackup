"""Render complete RouterOS installers without interpolating untrusted CLI text as code."""

import hashlib
import ipaddress
import re
import secrets
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "mikrotik" if (ROOT / "mikrotik").is_dir() else Path("/usr/local/share/mkbackup/mikrotik")


def quote(value):
    return (
        '"'
        + str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        + '"'
    )


def substitute(template, values):
    def replace(match):
        return str(values[match.group(1)])

    return re.sub(r"@([A-Z_]+)@", replace, template)


def render(
    router, major, host, port, base_url, job_owner, status_token, private_key=None, host_key=None, password=None
):
    from common import NAME, public_key

    name = router["name"]
    address = str(ipaddress.IPv4Address(host))
    url = urlsplit(base_url)
    if url.port is not None and not 1 <= url.port <= 65535:
        raise ValueError("Invalid HTTPS port")
    if (
        not NAME.fullmatch(name)
        or type(router["max_bytes"]) is not int
        or router["max_bytes"] < 1
        or url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or url.path not in ("", "/")
        or not NAME.fullmatch(job_owner)
        or major not in (6, 7)
        or not 1 <= port <= 65535
        or not re.fullmatch(r"[A-Za-z0-9_-]{43}", status_token)
    ):
        raise ValueError("Invalid deployment endpoint, owner or token")
    # Restrict the URL to safe DNS/IPv4 names and an optional numeric port.
    if not re.fullmatch(r"[A-Za-z0-9.-]+(?::[0-9]{1,5})?", url.netloc):
        raise ValueError("Invalid HTTPS authority")
    base_url = base_url.rstrip("/")
    managed = "mkbackup-managed:v1:" + name
    marker = managed + "|"
    if major == 6:
        if not password or not re.fullmatch(r"[A-Za-z0-9_-]{43}", password):
            raise ValueError("Expected a generated FTP credential")
        credentials = ':log warning "mkbackup: RouterOS 6 uses unencrypted FTP; HTTPS protects provisioning only"'
        upload = (
            f"/tool fetch mode=ftp address={address} port={port} user={quote(name)} password=$ftpPassword upload=yes"
        )
        version_check = ':if ([:pick $version 0 5] != "6.49.") do={ :error "RouterOS 6.49.x required" }'
        export = "/export hide-sensitive file=($prefix . $basename)"
        cleanup = "# No temporary private-key file for FTP."
    else:
        host_key = public_key(host_key)
        if not private_key or not private_key.startswith("-----BEGIN RSA PRIVATE KEY-----") or len(private_key) > 4095:
            raise ValueError("Expected RSA 3072 PKCS#1 PEM within RouterOS file-content limit")
        keybase = "mkbackup-key-" + secrets.token_hex(8)
        keyfile = keybase + ".txt"
        credentials = f"""# Fail before importing credentials when host verification is unavailable.
        :local validation [/ip ssh get known-hosts-validation]
        :local pinned [/ip ssh known-hosts find where host={address} and port={port}]
        :if ([:len $pinned] > 1) do={{ :error "ambiguous server pins" }}
        :if ([:len $pinned] = 1) do={{
            :if ([/ip ssh known-hosts get $pinned key] != {quote(host_key)}) do={{ :error "server key mismatch" }}
        }} else={{ /ip ssh known-hosts add host={address} port={port} key={quote(host_key)} comment={quote(managed)} }}
        /ip ssh set known-hosts-validation=yes
        :if ([:len [/file find where name={quote(keyfile)}]] > 0) do={{ :error "key file conflict" }}
        /file print file={quote(keybase)}
        :set keyCreated true
        :delay 1s
        /file set [find where name={quote(keyfile)}] contents={quote(private_key)}
        /user ssh-keys private import user={quote(job_owner)} private-key-file={quote(keyfile)} passphrase=""
        /file remove [find where name={quote(keyfile)}]"""
        upload = f"/tool fetch mode=sftp address={address} port={port} user={quote(name)} upload=yes sftp-known-hosts-ignore=no"
        version_check = ':if ([:pick $version 0 2] != "7.") do={ :error "capable RouterOS 7 required" }'
        export = "/export file=($prefix . $basename)"
        cleanup = f":if ($keyCreated) do={{ /file remove [find where name={quote(keyfile)}] }}"
    credential_data = (password or "-" * 43) + "\n" + status_token + "\n"
    credentials += f"""
        # Runtime credentials are files, so configuration export cannot include their contents.
        /file print file=($prefix . "mkbackup-credentials")
        :delay 1s
        /file set [find where name=($prefix . "mkbackup-credentials.txt")] contents={quote(credential_data)}
        :if ([/file get [find where name=($prefix . "mkbackup-credentials.txt")] contents] != {quote(credential_data)}) do={{ :error "credential file write failed" }}"""
    values = dict(
        ROUTER=name,
        MARKER=quote(marker),
        MANAGED=quote(managed),
        FILE_PATTERN=quote("^" + re.escape(name) + r"-[0-9]+\.rsc$"),
        TIMESTAMP_HELPER=(TEMPLATES / "timestamp.rsc").read_text(),
        MAX_BYTES=router["max_bytes"],
        EXPORT=export,
        BASE_URL=quote(base_url),
        UPLOAD_PAYLOAD=upload + ' src-path=($prefix . $current) dst-path=("/upload/" . $current)',
        UPLOAD_MARKER=upload + ' src-path=$markerFile dst-path=("/upload/" . $current . ".done.json")',
    )
    job = substitute((TEMPLATES / "job-export.rsc.in").read_text(), values)
    values.update(
        JOB_OWNER=quote(job_owner),
        CREDENTIALS=credentials,
        CLEANUP=cleanup,
        VERSION_CHECK=version_check,
        JOB_SOURCE=quote(job),
        PROBE_NAME=quote("mkbackup-owner-" + secrets.token_hex(8)),
        START_TIME=quote(
            "03:" + str(int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], "big") % 31).zfill(2) + ":00"
        ),
    )
    installer = substitute((TEMPLATES / "install.rsc.in").read_text(), values)
    return installer.encode()
