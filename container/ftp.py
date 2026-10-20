"""Explicit legacy plaintext FTP, isolated to incoming directories."""

import ipaddress
import json
import os
import signal
import socket
import subprocess
import sys
from pathlib import Path

from common import directory
from prepare import prepare


def main():
    address = str(ipaddress.IPv4Address(os.environ["FTP_PUBLIC_ADDRESS"]))
    low = int(os.environ.get("FTP_PASSIVE_MIN", "15110"))
    high = int(os.environ.get("FTP_PASSIVE_MAX", "15119"))
    if not 1024 <= low <= high <= 65535 or high - low > 99:
        raise ValueError("Invalid FTP passive range")
    prepare("ftp")
    from account_refresh import start_refresh

    start_refresh("ftp")
    directory("/run/vsftpd")
    directory("/run/vsftpd/empty")
    config = Path("/etc/vsftpd-mkbackup.conf").read_text()
    for token, value in (("PUBLIC_ADDRESS", address), ("PASSIVE_MIN", low), ("PASSIVE_MAX", high)):
        config = config.replace("@" + token + "@", str(value))
    Path("/run/mkbackup/vsftpd.conf").write_text(config)
    # vsftpd deliberately refuses symlink/non-regular log files such as
    # /dev/stdout. Receive native syslog over a bounded Unix datagram socket,
    # forwarding to Docker's rotated log driver without a growing log file.
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as logger:
        logger.bind("/dev/log")
        # Jailed vsftpd workers drop UID; they must still send native syslog.
        os.chmod("/dev/log", 0o666)  # nosec B103
        logger.settimeout(0.5)
        daemon = subprocess.Popen(["/usr/sbin/vsftpd", "/run/mkbackup/vsftpd.conf"])

        def terminate(signum, frame):
            daemon.terminate()

        signal.signal(signal.SIGTERM, terminate)
        signal.signal(signal.SIGINT, terminate)
        try:
            while daemon.poll() is None:
                try:
                    message = logger.recv(8192).decode("utf-8", "replace")
                except socket.timeout:
                    continue
                print(json.dumps(dict(event="ftp", message=message)), flush=True)
        finally:
            if daemon.poll() is None:
                daemon.terminate()
            daemon.wait(timeout=5)
        if daemon.returncode:
            raise ValueError("FTP daemon exited")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError):
        sys.exit("FTP startup refused: check public IPv4, passive ports and account hashes")
