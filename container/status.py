"""Print collector status for local monitoring, without a network listener."""

import sys
from pathlib import Path

try:
    print(Path("/run/mkbackup/collector-status.json").read_text(), end="")
except OSError:
    sys.exit("Collector status is not available")
