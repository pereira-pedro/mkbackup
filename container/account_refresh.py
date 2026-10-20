"""Refresh container-local NSS/account state without restarting upload listeners."""

import os
import signal
import subprocess
import threading
import time

from common import atomic_json, directory, load_snapshot


def acknowledge(service, generation, healthy):
    atomic_json(
        "/acks/" + service + ".json", dict(generation=generation, healthy=healthy, heartbeat=time.time()), mode=0o644
    )


def start_refresh(service):
    if not os.environ.get("ROUTERS_SNAPSHOT"):
        return
    directory("/acks")

    def run():
        from prepare import prepare_accounts

        applied = None
        while True:
            try:
                generation, routers = load_snapshot()
                if generation != applied:
                    prepare_accounts(service, routers)
                    # A concurrent publish must not acknowledge a mixed generation.
                    if load_snapshot()[0] != generation:
                        continue
                    applied = generation
                acknowledge(service, applied, True)
            except (OSError, ValueError, KeyError):
                acknowledge(service, applied or 0, False)
            time.sleep(0.5)

    threading.Thread(target=run, daemon=True).start()


def supervise(command, service):
    start_refresh(service)
    daemon = subprocess.Popen(command)

    def stop(signum, frame):
        daemon.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        result = daemon.wait()
    finally:
        if daemon.poll() is None:
            daemon.terminate()
            daemon.wait(timeout=5)
    if result:
        raise ValueError("Upload listener exited")
