"""Compatibility import for the shared runtime RouterOS renderer."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "container"))
# Load by file to avoid recursively importing this compatibility module.
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "mkbackup_routeros", Path(__file__).resolve().parents[1] / "container/routeros.py"
)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
render = _module.render
quote = _module.quote
substitute = _module.substitute
