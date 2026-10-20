#!/usr/bin/env python3
"""Validate public files and export a source snapshot without local data or Git history."""

import argparse
import csv
import hashlib
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = (
    ".dockerignore",
    ".editorconfig",
    ".env.example",
    ".gitleaks.toml",
    ".gitignore",
    "Caddyfile",
    "CONTRIBUTING.md",
    "Dockerfile",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "docker-compose.yml",
    "docker-entrypoint.sh",
    "pyproject.toml",
    "requirements-dev.txt",
    "sshd_config",
    "vsftpd-mkbackup.conf",
)
PATTERNS = (
    "patches/*.patch",
    "container/*.py",
    "container/pam-ftp",
    "scripts/*.py",
    "tests/*.py",
    "tests/*.rsc.in",
    "docs/*.md",
    "docs/*.csv",
    "docs/*.cfg.example",
    "mikrotik/*.rsc",
    "mikrotik/*.rsc.in",
    ".github/*.yml",
    ".github/workflows/*.yml",
)
FORBIDDEN = {".git", "secrets", "__pycache__", ".DS_Store", "virtusers.txt"}
PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/]{40}")


def public_files(root=ROOT):
    paths = {root / name for name in ROOT_FILES}
    for pattern in PATTERNS:
        paths.update(root.glob(pattern))
    for path in sorted(paths):
        relative = path.relative_to(root)
        if FORBIDDEN.intersection(relative.parts) or any(
            part.startswith(".env") for part in relative.parts if part != ".env.example"
        ):
            raise ValueError(f"Private path cannot be published: {relative}")
        if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file():
            raise ValueError(f"Missing or symlinked publication file: {relative}")
        if path.stat().st_size > 1024 * 1024:
            raise ValueError(f"Source file exceeds 1 MiB: {relative}")
        data = path.read_bytes()
        if PRIVATE_KEY.search(data):
            raise ValueError(f"Private key material found: {relative}")
        data.decode("utf-8")
        if relative.as_posix() == "docs/router-inventory.csv":
            rows = [row for row in csv.reader(data.decode("utf-8").splitlines()) if any(row)]
            if len(rows) != 1:
                raise ValueError("Public inventory must contain only its header, never router data")
    return sorted(paths)


def check(root=ROOT):
    paths = public_files(root)
    included = {path.relative_to(root).as_posix() for path in paths}
    # Include untracked new source, but never ignored local secrets or artifacts.
    if (root / ".git").exists():
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-co", "--exclude-standard", "-z"], check=True, capture_output=True
        )
        unknown = sorted(
            {
                name
                for name in result.stdout.decode().split("\0")
                if name and (root / name).exists() and name not in included
            }
        )
        if unknown:
            raise ValueError("Unclassified files need review: " + ", ".join(unknown))
    for path in paths:
        if path.suffix != ".md":
            continue
        for target in re.findall(r"\[[^\]]*\]\(([^\s)]+)\)", path.read_text()):
            link = urlsplit(target)
            if link.scheme or link.netloc or not link.path:
                continue
            resolved = (path.parent / unquote(link.path)).resolve()
            try:
                relative = resolved.relative_to(root.resolve()).as_posix()
            except ValueError:
                raise ValueError(f"Documentation link escapes source tree: {path.name}") from None
            if relative not in included:
                raise ValueError(f"Broken/unpublished link in {path.relative_to(root)}: {target}")
    return paths


def history(root=ROOT):
    revisions = subprocess.check_output(["git", "-C", str(root), "rev-list", "--all"], text=True).splitlines()
    findings = []
    for revision in revisions:
        names = subprocess.check_output(["git", "-C", str(root), "ls-tree", "-r", "--name-only", revision], text=True)
        for name in names.splitlines():
            parts = Path(name).parts
            if FORBIDDEN.intersection(parts) or (Path(name).name.startswith(".env") and name != ".env.example"):
                findings.append((revision[:12], name))
    if findings:
        raise ValueError(
            "Private files remain in Git history (commit:path): "
            + ", ".join(commit + ":" + name for commit, name in findings)
        )


def export(output, root=ROOT):
    paths = check(root)
    if output.exists() or output.is_symlink() or output.with_suffix(".zip").exists():
        raise ValueError("Export destination or ZIP already exists; choose a new name")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()
    manifest = {}
    for path in paths:
        relative = path.relative_to(root)
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        manifest[relative.as_posix()] = hashlib.sha256(destination.read_bytes()).hexdigest()
    with zipfile.ZipFile(output.with_suffix(".zip"), "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in manifest:
            archive.write(output / name, output.name + "/" + name)
    output.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return len(paths)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "history", "export"))
    parser.add_argument("--output", type=Path, default=ROOT / "dist/mkbackup-public")
    args = parser.parse_args()
    if args.command == "history":
        history()
        print("No known private filenames in reachable Git history; also run Gitleaks.")
    elif args.command == "check":
        print(f"Validated {len(check())} public files and local documentation links; also run Gitleaks.")
    else:
        count = export(args.output)
        print(f"Exported {count} files to {args.output}; ZIP and SHA-256 manifest created alongside it.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
