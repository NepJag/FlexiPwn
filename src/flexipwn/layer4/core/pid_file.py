from __future__ import annotations

import os
from pathlib import Path


def write_pid(path: str | Path, pid: int | None = None) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(str(pid if pid is not None else os.getpid()))


def read_pid(path: str | Path) -> int | None:
    p = Path(path)
    if not p.exists():
        return None
    try:
        return int(p.read_text().strip())
    except (ValueError, OSError):
        return None


def is_running(pid: int) -> bool:
    """Devuelve True si el proceso pid existe."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def remove_pid_file(path: str | Path) -> None:
    p = Path(path)
    if p.exists():
        try:
            p.unlink()
        except OSError:
            pass
