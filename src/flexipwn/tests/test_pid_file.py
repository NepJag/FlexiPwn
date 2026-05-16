from __future__ import annotations

import os
from pathlib import Path

import pytest

from flexipwn.layer4.core.pid_file import (
    is_running,
    read_pid,
    remove_pid_file,
    write_pid,
)


def test_write_and_read_pid(tmp_path: Path):
    p = tmp_path / "daemon.pid"
    write_pid(p, 12345)
    assert read_pid(p) == 12345


def test_read_pid_missing_file_returns_none(tmp_path: Path):
    assert read_pid(tmp_path / "nope.pid") is None


def test_read_pid_corrupt_file_returns_none(tmp_path: Path):
    p = tmp_path / "daemon.pid"
    p.write_text("not-a-pid")
    assert read_pid(p) is None


def test_is_running_for_current_process_is_true():
    assert is_running(os.getpid()) is True


def test_is_running_for_invalid_pid_is_false():
    assert is_running(0) is False
    assert is_running(-1) is False


def test_is_running_for_dead_pid_is_false():
    # Crear y reapear un proceso para tener un PID definitivamente muerto.
    pid = os.fork() if hasattr(os, "fork") else None
    if pid is None:
        pytest.skip("os.fork no disponible en esta plataforma")
    if pid == 0:
        os._exit(0)
    os.waitpid(pid, 0)
    assert is_running(pid) is False


def test_remove_pid_file_idempotent(tmp_path: Path):
    p = tmp_path / "daemon.pid"
    write_pid(p, 1)
    remove_pid_file(p)
    assert not p.exists()
    # Segunda llamada no debe lanzar
    remove_pid_file(p)
