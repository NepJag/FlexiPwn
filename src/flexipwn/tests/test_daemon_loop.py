"""Unit tests del DaemonLoop con mocks de provider, super_monitor y CLI."""
from __future__ import annotations

import threading
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console
from sqlmodel import Session, create_engine

from flexipwn.layer1.provider import EnvironmentNotFoundError
from flexipwn.layer4.db.models import ExerciseRun, Participant, Scenario
from flexipwn.layer4.db.session import init_db


@pytest.fixture
def engine(tmp_path):
    db_path = tmp_path / "test.db"
    eng = create_engine(f"sqlite:///{db_path}", echo=False)
    init_db(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def patched_session(engine, monkeypatch):
    """Forza `get_session` a usar el engine in-memory de la fixture."""
    from flexipwn.layer4.db import session as session_mod

    @session_mod.contextmanager
    def fake_get_session(_engine=None):
        with Session(engine) as s:
            yield s

    monkeypatch.setattr(session_mod, "get_session", fake_get_session)
    # también para los módulos que ya importaron get_session por nombre
    import flexipwn.layer4.core.daemon_loop as loop_mod
    monkeypatch.setattr(loop_mod, "get_session", fake_get_session)
    import flexipwn.layer4.db.repository as repo_mod
    # repository no usa get_session directamente; lo dejamos
    return engine


def _seed_basic(session: Session, status: str = "running") -> tuple[ExerciseRun, Scenario, Participant]:
    yaml_text = """
title: T
description: ''
author: a
level: beginner
category: pwning
environment:
  image: img
  attacker_image: flexipwn-attacker
targets:
  - type: file_created
    path: /tmp
    description: t
condition: all
timeout_seconds: 60
"""
    scenario = Scenario(
        yaml_path="/tmp/x.yaml", yaml_content=yaml_text,
        title="T", description="", author="a", level="beginner",
        category="pwning", image="img", attacker_image="flexipwn-attacker",
        timeout_seconds=60,
    )
    participant = Participant(username="student-loop01", password_hash="h")
    session.add(scenario)
    session.add(participant)
    session.commit()
    session.refresh(scenario)
    session.refresh(participant)

    run = ExerciseRun(
        scenario_id=scenario.id, participant_id=participant.id,
        env_id="run-loop0001", status=status,
        attacker_ssh_port=2210,
    )
    session.add(run)
    session.commit()
    session.refresh(run)
    return run, scenario, participant


def _make_loop(provider_mock, super_mon_mock):
    from flexipwn.layer4.core.daemon_loop import DaemonLoop
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=120, no_color=True)
    with patch("flexipwn.layer4.core.daemon_loop.DockerRootlessProvider", return_value=provider_mock), \
         patch("flexipwn.layer4.core.daemon_loop.SuperMonitor", return_value=super_mon_mock):
        loop = DaemonLoop(console=console)
    loop._console_buf = buf  # type: ignore[attr-defined]
    return loop


def test_reconcile_marks_failed_when_container_missing(patched_session):
    with Session(patched_session) as s:
        run, _, _ = _seed_basic(s)
        run_id = run.id

    provider = MagicMock()
    provider.attach_existing.side_effect = EnvironmentNotFoundError("missing")
    super_mon = MagicMock()

    loop = _make_loop(provider, super_mon)
    loop._reconcile()

    with Session(patched_session) as s:
        run = s.get(ExerciseRun, run_id)
        assert run.status == "failed"
        assert "no existe" in (run.daemon_message or "").lower()


def test_handle_running_generates_credentials_and_registers(patched_session):
    with Session(patched_session) as s:
        run, _, _ = _seed_basic(s)
        run_id = run.id
        env_id = run.env_id

    provider = MagicMock()
    docker_env = MagicMock()
    docker_env.env_id = env_id
    docker_env.scenario_id = "s"
    docker_env.participant_id = "p"
    docker_env.volume_base_path = "/tmp"
    docker_env.container_attacker_name = f"flexipwn-{env_id}-attacker"
    provider.attach_existing.return_value = docker_env
    provider.get_capture_host_path.return_value = None
    provider.exec_run.return_value = MagicMock(exit_code=0, stdout="", stderr="")
    super_mon = MagicMock()

    loop = _make_loop(provider, super_mon)

    # Forzar handle_running para no depender del orchestrator real
    with patch("flexipwn.layer4.core.daemon_loop._build_orchestrator", return_value=MagicMock()):
        with Session(patched_session) as s:
            run = s.get(ExerciseRun, run_id)
            loop._handle_running(run)

    # Provider exec_run llamado para useradd + chpasswd (sin sudo: política)
    assert provider.exec_run.call_count >= 2
    # SuperMonitor add_environment fue invocado
    super_mon.add_environment.assert_called_once()

    # Credenciales escritas a DB
    with Session(patched_session) as s:
        run = s.get(ExerciseRun, run_id)
        assert run.attacker_ssh_username == "student-loop01"
        assert run.attacker_ssh_password is not None
        assert len(run.attacker_ssh_password) >= 8


def test_handle_stopping_destroys_and_finalizes(patched_session):
    with Session(patched_session) as s:
        run, _, _ = _seed_basic(s, status="stopping")
        run.progress = 0.5
        s.add(run)
        s.commit()
        run_id = run.id
        env_id = run.env_id

    provider = MagicMock()
    super_mon = MagicMock()
    loop = _make_loop(provider, super_mon)

    with Session(patched_session) as s:
        run = s.get(ExerciseRun, run_id)
        loop._handle_stopping(run)

    super_mon.remove_environment.assert_called_once_with(env_id)
    provider.destroy.assert_called_once_with(env_id)
    with Session(patched_session) as s:
        run = s.get(ExerciseRun, run_id)
        assert run.status == "stopped"  # progress < 1.0
        assert run.finished_at is not None
