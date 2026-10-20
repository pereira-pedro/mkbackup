#!/usr/bin/env python3
"""Local key generation, enrollment, rotation, revocation and RouterOS bundles."""

import argparse
import fcntl
import ipaddress
import json
import os
import secrets
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "container"))
from common import NAME, atomic_json, fingerprint, load_routers, parse_routers, public_key

COMPOSE = ["docker", "compose", "--project-directory", str(ROOT)]


def keygen(path, kind, comment):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() or path.with_suffix(path.suffix + ".pub").exists():
        raise ValueError("Key path already exists; refusing to overwrite")
    args = ["ssh-keygen", "-q", "-t", kind, "-N", "", "-C", comment, "-f", str(path)]
    if kind == "rsa":
        args += ["-b", "3072", "-m", "PEM"]
    subprocess.run(args, check=True)
    path.chmod(0o600)


def save_registry(path, routers):
    value = dict(version=2, routers=routers)
    parse_routers(json.dumps(value))
    atomic_json(path, value)


def compose_environment(registry):
    return dict(
        os.environ,
        ROUTERS_FILE=str(registry.resolve()),
        FTP_PASSWORDS_FILE=str(registry.parent / "ftp_passwords.json"),
        ENROLLMENT_KEY_FILE=str(registry.parent / "enrollment.key"),
    )


def control(operation, **parameters):
    result = subprocess.run(
        COMPOSE + ["exec", "-T", "provisioner", "python3", "/usr/local/lib/mkbackup/provisioner_client.py"],
        input=json.dumps(dict(operation=operation, **parameters)),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ValueError(
            "Provisioning service unavailable or request rejected; check admin enrollment status. Use --offline only for pre-deployment bootstrap."
        )
    return json.loads(result.stdout)


def apply_registry(registry):
    control("apply")
    routers = control("registry")["routers"]
    services = ["sftp", "collector"] + (["ftp"] if any(row["transport"] == "ftp" for row in routers) else [])
    subprocess.run(
        COMPOSE + ["up", "-d", "--no-build", "--force-recreate", "--wait", "--wait-timeout", "60"] + services,
        check=True,
    )


def deployment(args, registry):
    import hashlib
    import time

    if args.deployment_command == "list":
        print(json.dumps(control("deployments"), indent=2))
        return
    if args.deployment_command == "revoke":
        control("mutate", action="revoke", name=args.name)
        try:
            apply_registry(registry)
        except (ValueError, subprocess.CalledProcessError):
            sys.exit("REVOCATION STAGED: terminate transport sessions by repairing Compose and repeating apply")
        print("Enrollment/status credentials revoked and existing transport sessions terminated.")
        return
    current = control("registry")["routers"]
    exists = any(row["name"] == args.name for row in current)
    if exists and not args.replace:
        raise ValueError("Router already exists; use --replace for deliberate credential rotation/re-enrollment")
    defaults = control("list")["defaults"]
    if args.base_url and args.base_url.rstrip("/") != defaults["base_url"]:
        raise ValueError("--base-url must match the centrally configured ENROLLMENT_BASE_URL")
    spec = dict(
        name=args.name,
        major=args.routeros_major,
        host=args.host,
        port=args.port or defaults["ftp_port" if args.routeros_major == 6 else "sftp_port"],
        job_owner=args.job_owner,
    )
    owner = hashlib.sha256(b"mkbackup-cli").hexdigest()
    job = control("rotate" if exists else "create", spec=spec, owner=owner, request=secrets.token_hex(32))["id"]
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        state = control("job", id=job, owner=owner)
        if state["state"] == "failed":
            raise ValueError(state["error"])
        if state["state"] == "ready":
            break
        time.sleep(0.3)
    else:
        raise ValueError("Provisioning still pending; check the admin enrollment status")
    result = control("instructions", id=job, owner=owner)
    expires = datetime.fromtimestamp(result["expires_at"], timezone.utc).isoformat()
    print(f"PRIVATE enrollment instructions for {args.name}; one download; expires {expires}")
    print(
        '/tool fetch url="'
        + result["base_url"]
        + '/" check-certificate=yes http-header-field="Authorization: Bearer '
        + result["token"]
        + '" dst-path=mkbackup-install.rsc'
    )
    print("/import file-name=mkbackup-install.rsc")


def bundle(args, router, secrets_dir):
    if router["transport"] != "sftp":
        raise ValueError("Manual bundles require an SFTP identity; use deployment issue --routeros-major 6 for FTP")
    address = str(ipaddress.IPv4Address(args.host))
    if not 1 <= args.port <= 65535 or not NAME.fullmatch(args.job_owner):
        raise ValueError("Invalid port or RouterOS job owner")
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    hostkey = subprocess.check_output(
        ["ssh-keygen", "-y", "-P", "", "-f", str(secrets_dir / "ssh_host_rsa_key")], text=True
    ).strip()
    hostkey = public_key(hostkey)
    name = router["name"]
    template = (ROOT / "mikrotik/upload-routeros7.rsc.in").read_text()
    for key, value in {"HOST": address, "PORT": args.port, "ROUTER": name, "MAX_BYTES": router["max_bytes"]}.items():
        template = template.replace("@" + key + "@", str(value))
    (args.output / "upload.rsc").write_text(template)
    enrollment = (
        "# RouterOS 7 capability-gated template. Run as an administrator.\n"
        "# Verify this host key out-of-band before importing.\n"
        f"# Server RSA fingerprint: {fingerprint(hostkey)}\n"
        "/ip/ssh/set known-hosts-validation=yes\n"
        f'/ip/ssh/known-hosts/add host={address} port={args.port} key="{hostkey}" comment="mkbackup"\n'
        f'/user/ssh-keys/private/import user="{args.job_owner}" private-key-file="{name}.pem"\n'
        f'/file/remove [find where name="{name}.pem"]\n'
        "# Import upload.rsc under the SAME job owner as the scheduled backup.\n"
        "# Then call $mkbackupUpload after your existing backup generation.\n"
    )
    (args.output / "enroll.rsc").write_text(enrollment)
    known_host = address if args.port == 22 else f"[{address}]:{args.port}"
    (args.output / "server-known-hosts").write_text(f"{known_host} {hostkey}\n")
    print(
        "Wrote public provisioning templates. Transfer the router private key separately over authenticated management access."
    )


def main():
    global COMPOSE
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Bootstrap seed files before first deployment only; never edits the running registry",
    )
    parser.add_argument("--secrets-dir", type=Path, default=ROOT / "secrets")
    parser.add_argument("--compose-file", type=Path, action="append", help="Repeat for isolated Compose overrides")
    parser.add_argument("--project-name", help="Explicit Compose project; use the existing production project name")
    parser.add_argument(
        "--env-file",
        type=Path,
        action="append",
        help="Compose environment file; repeat in precedence order, later files override earlier ones",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Generate persistent server host keys and an empty registry")
    generate = commands.add_parser("keygen", help="Generate a per-router RSA/PEM key on this management workstation")
    generate.add_argument("name")
    generate.add_argument("--output-dir", type=Path, required=True)
    enroll = commands.add_parser("enroll", help="Add an account or overlap a new key; existing UID stays fixed")
    enroll.add_argument("name")
    enroll.add_argument("--public-key", type=Path, required=True)
    enroll.add_argument("--uid", type=int)
    enroll.add_argument("--max-bytes", type=int)
    enroll.add_argument("--expected-interval-seconds", type=int)
    for command in ("revoke-key", "disable"):
        action = commands.add_parser(
            command, help="Stage registry change and recreate both services to terminate active sessions"
        )
        action.add_argument("name")
        if command == "revoke-key":
            action.add_argument("--fingerprint", required=True)
        action.add_argument(
            "--stage-only", action="store_true", help="Do NOT revoke live sessions yet; operator must apply separately"
        )
    commands.add_parser("apply", help="Recreate both services after registry changes; terminates all sessions")
    deploy = commands.add_parser("deployment", help="Issue, revoke or list one-download RouterOS installers")
    actions = deploy.add_subparsers(dest="deployment_command", required=True)
    issue = actions.add_parser("issue", help="Generate credentials, apply accounts, then issue a 10-minute HTTPS token")
    issue.add_argument("name")
    issue.add_argument("--routeros-major", type=int, choices=(6, 7), required=True)
    issue.add_argument("--host", required=True, help="Backup server public IPv4")
    issue.add_argument("--port", type=int, help="Default: FTP 15101 or SFTP 15100; must match published port")
    issue.add_argument("--base-url", help="Must match the configured ENROLLMENT_BASE_URL")
    issue.add_argument(
        "--job-owner", required=True, help="Administrator who will import the script and own the scheduled job"
    )
    issue.add_argument(
        "--replace",
        action="store_true",
        help="Rotate/re-enroll an existing identity; FTP credentials change immediately",
    )
    actions.add_parser("list")
    revoke = actions.add_parser("revoke")
    revoke.add_argument("name")
    commands.add_parser("retention-preview", help="Read-only report of files retained/pruned; never enables deletion")
    render = commands.add_parser("bundle", help="Render version-specific templates; no changes are sent to routers")
    render.add_argument("name")
    render.add_argument("--host", required=True, help="Verified server IPv4 address")
    render.add_argument("--port", type=int, default=15100)
    render.add_argument(
        "--routeros-major",
        type=int,
        choices=(7,),
        default=7,
        help="Manual SFTP bundles require capable RouterOS 7; use deployment issue for v6 FTP",
    )
    render.add_argument("--job-owner", required=True)
    render.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.project_name:
        COMPOSE += ["--project-name", args.project_name]
    for env_file in args.env_file or []:
        COMPOSE += ["--env-file", str(env_file.resolve())]
    for compose_file in args.compose_file or []:
        COMPOSE += ["--file", str(compose_file.resolve())]
    if hasattr(args, "name") and (not NAME.fullmatch(args.name) or args.name in {"root", "sshd", "nobody", "ftp"}):
        parser.error("Invalid or reserved router name")
    directory = args.secrets_dir.resolve()
    if args.command == "keygen":
        execute(args, directory)
        return
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (directory / ".manage.lock").open("a") as lock:
        # Keep stable UID allocation, credential staging and live apply together.
        fcntl.flock(lock, fcntl.LOCK_EX)
        execute(args, directory)


def execute(args, directory):
    registry = directory / "routers.json"
    if args.command == "init":
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        for kind in ("rsa", "ed25519"):
            destination = directory / ("ssh_host_" + kind + "_key")
            if not destination.exists():
                keygen(destination, kind, "mkbackup-server")
            pub = Path(str(destination) + ".pub")
            if not pub.exists():
                pub.write_text(
                    subprocess.check_output(["ssh-keygen", "-y", "-P", "", "-f", str(destination)], text=True)
                )
                pub.chmod(0o600)
        if not registry.exists():
            save_registry(registry, [])
        if not (directory / "ftp_passwords.json").exists():
            atomic_json(directory / "ftp_passwords.json", {})
        keypath = directory / "enrollment.key"
        if not keypath.exists():
            with keypath.open("xb") as output:
                output.write(secrets.token_bytes(32))
            keypath.chmod(0o600)
        print("Initialized persistent host keys. Keep this directory private and backed up.")
        return
    if args.command == "deployment":
        deployment(args, registry)
        return
    if args.command == "retention-preview":
        subprocess.run(
            COMPOSE
            + [
                "run",
                "--rm",
                "--no-deps",
                "--entrypoint",
                "python3",
                "collector",
                "/usr/local/lib/mkbackup/retention.py",
            ],
            check=True,
            env=compose_environment(registry),
        )
        return
    if args.command == "keygen":
        keygen(args.output_dir / (args.name + ".pem"), "rsa", args.name)
        print("Generated a private RSA/PEM key and its public key; enroll only the .pub file on the server.")
        return
    if args.command == "apply":
        load_routers(registry)
        apply_registry(registry)
        return
    if not args.offline and args.command in ("enroll", "disable", "revoke-key"):
        parameters = dict(name=args.name)
        if args.command == "enroll":
            parameters.update(
                public_key=args.public_key.read_text(),
                uid=args.uid,
                max_bytes=args.max_bytes,
                expected_interval_seconds=args.expected_interval_seconds,
            )
        elif args.command == "revoke-key":
            parameters["fingerprint"] = args.fingerprint
        control("mutate", action=args.command, **parameters)
        if args.command == "enroll" or args.stage_only:
            print("Registry staged in provisioning storage; run manage.py apply before activation/session revocation.")
        else:
            apply_registry(registry)
            print("Registry applied and previous sessions terminated.")
        return
    routers = load_routers(registry) if args.offline else control("registry")["routers"]
    router = next((entry for entry in routers if entry["name"] == args.name), None)
    if args.command == "enroll":
        if router is not None and router["transport"] != "sftp":
            raise ValueError("FTP identities cannot be enrolled with an SFTP key")
        key = public_key(args.public_key.read_text())
        if router is None:
            uid = args.uid if args.uid is not None else max([9999] + [entry["uid"] for entry in routers]) + 1
            router = dict(name=args.name, uid=uid, keys=[], enabled=True)
            routers.append(router)
        elif args.uid is not None and args.uid != router["uid"]:
            raise ValueError("Existing UID/GID cannot be changed")
        if key not in router["keys"]:
            router["keys"].append(key)
        router["enabled"] = True
        for option in ("max_bytes", "expected_interval_seconds"):
            if getattr(args, option) is not None:
                router[option] = getattr(args, option)
        save_registry(registry, routers)
        print(
            f"Enrolled {args.name}, UID/GID {router['uid']}, {fingerprint(key)}. Run manage.py apply before activation."
        )
        return
    if router is None:
        raise ValueError("Router is not enrolled")
    if args.command == "bundle":
        bundle(args, router, directory)
        return
    if args.command == "disable":
        router["enabled"] = False
    else:
        retained = [key for key in router["keys"] if fingerprint(key) != args.fingerprint]
        if len(retained) == len(router["keys"]):
            raise ValueError("Fingerprint does not belong to this router")
        router["keys"] = retained
        if not retained:
            router["enabled"] = False
    save_registry(registry, routers)
    if args.stage_only:
        print("STAGED ONLY: live credentials and sessions remain valid until manage.py apply succeeds.")
    else:
        try:
            apply_registry(registry)
        except (OSError, subprocess.CalledProcessError):
            sys.exit(
                "LIVE REVOCATION FAILED: registry is updated, but active sessions may remain. Fix Compose and run manage.py apply."
            )
        print("Registry applied; all previous SFTP sessions were terminated.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit("Management action failed: " + str(error))
