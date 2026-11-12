"""Link/junction detection shared by evidence.py, report.py and scope_guard.py (stdlib, Python 3.8+)."""
from __future__ import annotations

import os
from pathlib import Path

_REPARSE_POINT = 0x400  # Windows FILE_ATTRIBUTE_REPARSE_POINT: symlinks, junctions, mount points, cloud placeholders


def is_link(path) -> bool:
    """True for symlinks AND Windows junctions/reparse points. Never follows the link."""
    p = Path(path)
    try:
        if p.is_symlink():
            return True
        return bool(getattr(os.lstat(p), "st_file_attributes", 0) & _REPARSE_POINT)
    except OSError:
        return False


def reject_links_under(base, rel) -> None:
    """Raise ValueError if any existing component of base/rel is a link (base itself is not checked)."""
    current = Path(base)
    for part in Path(rel).parts:
        current = current / part
        if is_link(current):
            raise ValueError(f"Refusing to use a path through a link/junction: {current}")
