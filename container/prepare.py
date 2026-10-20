"""Provision ephemeral identities and launch a key-only, chrooted OpenSSH server."""

import grp
import os
import pwd
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

from common import directory, load_routers, public_key


def atomic_text(path, content, mode):
    import tempfile

    fd, temporary = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def prepare_accounts(transport="sftp", routers=None):
    os.umask(0o077)
    routers = load_routers() if routers is None else routers
    active = [router for router in routers if router["enabled"] and router.get("transport", "sftp") == transport]
    directory("/run/mkbackup")
    directory("/run/mkbackup/keys", 0o700)
    directory("/run/mkbackup/authorized_keys")
    directory("/run/sshd")
    directory("/srv/sftp")
    # A random, discarded password hash keeps the Unix account usable for public
    # keys with UsePAM=no. Every password authentication method is disabled.
    unusable = (
        subprocess.check_output(
            ["/usr/bin/openssl", "passwd", "-6", "-stdin"], input=secrets.token_bytes(48).hex().encode()
        )
        .decode()
        .strip()
    )
    passwd, group, shadow = [], [], []
    for router in active:
        name, uid = router["name"], router["uid"]
        try:
            existing = pwd.getpwnam(name)
        except KeyError:
            existing = None
        if existing and existing.pw_uid != uid:
            raise ValueError("Router identity conflicts with an existing account")
        group_name = f"mkbackup-sftp-{uid}" if transport == "sftp" else name
        for lookup, expected in ((pwd.getpwuid, name), (grp.getgrgid, group_name)):
            try:
                identity = lookup(uid)
            except KeyError:
                continue
            if identity[0] != expected:
                raise ValueError("UID/GID conflicts with a system identity")
        account_home = f"/srv/sftp/{name}" if transport == "ftp" else "/upload"
        passwd.append(f"{name}:x:{uid}:{uid}:Backup router:{account_home}:/usr/sbin/nologin\n")
        group.append(f"{group_name}:x:{uid}:\n")
        shadow.append(f"{name}:{unusable}:20000:0:99999:7:::\n")
        home = Path("/srv/sftp") / name
        directory(home)
        upload = home / "upload"
        if upload.exists() and (upload.lstat().st_uid not in (0, uid)):
            raise ValueError("Refusing to reassign an existing upload directory")
        directory(upload, 0o700, uid, uid)
        authorized = Path("/run/mkbackup/authorized_keys") / name
        atomic_text(authorized, "".join("restrict " + key + "\n" for key in router["keys"]), 0o644)
    for filename, content, mode in (("passwd", passwd, 0o644), ("group", group, 0o644), ("shadow", shadow, 0o600)):
        if transport == "ftp" and filename == "shadow":
            continue
        target = Path("/var/lib/extrausers") / filename
        atomic_text(target, "".join(content), mode)
    if transport == "ftp":
        from common import load_ftp_passwords

        passwords = load_ftp_passwords()
        if any(router["name"] not in passwords for router in active):
            raise ValueError("Missing FTP password hash")
        atomic_text(
            Path("/var/lib/extrausers/shadow"),
            "".join(f"{router['name']}:{passwords[router['name']]}:20000:0:99999:7:::\n" for router in active),
            0o600,
        )
        atomic_text(Path("/run/mkbackup/ftp-users"), "".join(router["name"] + "\n" for router in active), 0o600)
    # Remove key authorization for disabled/removed identities. Existing sessions
    # are terminated only by explicit CLI revocation, not routine enrollment.
    allowed = {router["name"] for router in active}
    for key_path in Path("/run/mkbackup/authorized_keys").iterdir():
        if key_path.name not in allowed:
            key_path.unlink()


def prepare(transport="sftp"):
    prepare_accounts(transport)
    if transport == "ftp":
        return
    for name in ("ssh_host_rsa_key", "ssh_host_ed25519_key"):
        destination = Path("/run/mkbackup/keys") / name
        shutil.copyfile(Path("/run/secrets") / name, destination)
        destination.chmod(0o600)
        exported = subprocess.check_output(
            ["/usr/bin/ssh-keygen", "-y", "-P", "", "-f", str(destination)], text=True, stderr=subprocess.DEVNULL
        )
        if name == "ssh_host_rsa_key":
            public_key(exported)
        elif not exported.startswith("ssh-ed25519 "):
            raise ValueError("Expected an Ed25519 server host key")
    config = Path("/etc/ssh/mkbackup.conf").read_text()
    Path("/run/mkbackup/sshd_config").write_text(config)
    subprocess.run(["/usr/sbin/sshd", "-t", "-f", "/run/mkbackup/sshd_config"], check=True)


if __name__ == "__main__":
    from account_refresh import supervise

    try:
        prepare()
        supervise(["/usr/sbin/sshd", "-D", "-e", "-f", "/run/mkbackup/sshd_config"], "sftp")
    except (OSError, ValueError, subprocess.CalledProcessError):
        sys.exit("Startup refused: check registry, host keys, identities and directory permissions")
