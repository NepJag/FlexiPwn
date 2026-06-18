"""Tests de la limpieza por el educador.

Cubre `scenario remove`, y los dos `reset-all` del laboratorio (scenario /
participant) que comparten `cli/cleanup._perform_reset_all`. Dos niveles:
  - Repositorio (DB real en SQLite temporal): delete_scenario,
    reset_all_keep_participants, reset_all_keep_scenarios.
  - CLI/REPL (mocks, estilo test_batch_start_failures): guard, happy path,
    reset-all por modo, y que la confirmación destructiva no sea saltable.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console
from sqlmodel import Session, create_engine, select

from flexipwn.layer4.db import models as _models
from flexipwn.layer4.db.models import (
    ExerciseRun,
    Participant,
    RunEvent,
    Scenario,
    TargetResult,
)
from flexipwn.layer4.db.session import init_db
from flexipwn.layer4.db import repository
from flexipwn.layer4.cli import cleanup as cleanup_mod
from flexipwn.layer4.cli import scenario as scenario_mod
from flexipwn.layer4.cli.cleanup import _perform_reset_all
from flexipwn.layer4.cli.scenario import _perform_scenario_removal
from flexipwn.layer4.core.repl import FlexiPwnREPL


# ---------------------------------------------------------------------------
# Fixtures DB (mismo patrón que test_db.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'test.db'}", echo=False)
    init_db(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine):
    with Session(engine) as s:
        yield s


def _mk_scenario(session: Session, title: str = "S") -> Scenario:
    sc = Scenario(
        yaml_path="/tmp/s.yaml",
        yaml_content="title: s",
        title=title,
        description="",
        author="a",
        level="beginner",
        category="pwning",
        image="img:latest",
    )
    session.add(sc)
    session.commit()
    session.refresh(sc)
    return sc


def _mk_participant(session: Session, username: str = "student-x") -> Participant:
    p = Participant(username=username, password_hash="h")
    session.add(p)
    session.commit()
    session.refresh(p)
    return p


def _mk_run(session, sc, p, env_id, status="stopped") -> ExerciseRun:
    r = ExerciseRun(
        scenario_id=sc.id, participant_id=p.id, env_id=env_id, status=status
    )
    session.add(r)
    session.commit()
    session.refresh(r)
    return r


def _mk_child_rows(session, run) -> None:
    session.add(
        TargetResult(
            run_id=run.id,
            target_index=0,
            target_type="file_created",
            description="d",
        )
    )
    session.add(
        RunEvent(
            run_id=run.id,
            timestamp=datetime.now(timezone.utc),
            monitor_type="fs",
            event_type="created",
            details_json="{}",
        )
    )
    session.commit()


# ---------------------------------------------------------------------------
# Repositorio
# ---------------------------------------------------------------------------


class TestRepository:
    def test_delete_scenario_removes_only_definition(self, session):
        sc = _mk_scenario(session)
        repository.delete_scenario(session, sc.id)
        assert repository.get_scenario(session, sc.id) is None

    def test_reset_all_keep_participants(self, session):
        sc = _mk_scenario(session)
        p = _mk_participant(session)
        run = _mk_run(session, sc, p, "run-1", status="completed")
        _mk_child_rows(session, run)

        counts = repository.reset_all_keep_participants(session)

        assert counts == {"events": 1, "targets": 1, "runs": 1, "scenarios": 1}
        assert repository.list_scenarios(session) == []
        assert repository.list_runs(session) == []
        assert list(session.exec(select(TargetResult)).all()) == []
        assert list(session.exec(select(RunEvent)).all()) == []
        # Los participantes se conservan.
        assert len(repository.list_participants(session)) == 1

    def test_reset_all_keep_scenarios(self, session):
        sc = _mk_scenario(session)
        p = _mk_participant(session)
        run = _mk_run(session, sc, p, "run-1", status="completed")
        _mk_child_rows(session, run)

        counts = repository.reset_all_keep_scenarios(session)

        assert counts == {"events": 1, "targets": 1, "runs": 1, "participants": 1}
        assert repository.list_participants(session) == []
        assert repository.list_runs(session) == []
        assert list(session.exec(select(TargetResult)).all()) == []
        assert list(session.exec(select(RunEvent)).all()) == []
        # Los escenarios se conservan.
        assert len(repository.list_scenarios(session)) == 1


# ---------------------------------------------------------------------------
# CLI (mocks)
# ---------------------------------------------------------------------------


def _session_cm():
    cm = MagicMock()
    cm.__enter__.return_value = MagicMock()
    cm.__exit__.return_value = False
    return cm


def _fake_console() -> tuple[Console, StringIO]:
    buf = StringIO()
    return Console(file=buf, force_terminal=False, no_color=True, width=200), buf


_TERMINAL = ("completed", "failed", "timeout", "stopped")


class TestScenarioRemove:
    def test_guard_refuses_when_active_runs(self):
        sid = uuid.uuid4()
        scenario = SimpleNamespace(id=sid, title="S")
        runs = [SimpleNamespace(id=uuid.uuid4(), env_id="run-1", status="running")]
        repo = MagicMock()
        repo.TERMINAL_STATUSES = _TERMINAL
        repo.get_scenario.return_value = scenario
        repo.list_runs.return_value = runs
        provider_cls = MagicMock()
        console, buf = _fake_console()

        with patch.object(scenario_mod, "repository", repo), patch.object(
            scenario_mod, "get_session", side_effect=lambda: _session_cm()
        ), patch.object(
            scenario_mod, "DockerRootlessProvider", provider_cls
        ), patch.object(scenario_mod, "console", console):
            result = _perform_scenario_removal(str(sid), confirm=lambda msg: True)

        assert result is False
        provider_cls.assert_not_called()
        repo.delete_run.assert_not_called()
        repo.delete_scenario.assert_not_called()
        assert "runs activos" in buf.getvalue()

    def test_happy_path_destroys_and_deletes(self):
        sid = uuid.uuid4()
        scenario = SimpleNamespace(id=sid, title="S")
        runs = [
            SimpleNamespace(id=uuid.uuid4(), env_id="run-1", status="completed"),
            SimpleNamespace(id=uuid.uuid4(), env_id="run-2", status="stopped"),
        ]
        repo = MagicMock()
        repo.TERMINAL_STATUSES = _TERMINAL
        repo.get_scenario.return_value = scenario
        repo.list_runs.return_value = runs
        provider = MagicMock()
        provider_cls = MagicMock(return_value=provider)
        console, _ = _fake_console()

        with patch.object(scenario_mod, "repository", repo), patch.object(
            scenario_mod, "get_session", side_effect=lambda: _session_cm()
        ), patch.object(
            scenario_mod, "DockerRootlessProvider", provider_cls
        ), patch.object(scenario_mod, "FlexiPwnConfig", MagicMock()), patch.object(
            scenario_mod, "console", console
        ):
            result = _perform_scenario_removal(str(sid), confirm=lambda msg: True)

        assert result is True
        assert provider.destroy.call_count == 2
        assert repo.delete_run.call_count == 2
        repo.delete_scenario.assert_called_once()

    def test_cancel_returns_false(self):
        sid = uuid.uuid4()
        scenario = SimpleNamespace(id=sid, title="S")
        repo = MagicMock()
        repo.TERMINAL_STATUSES = _TERMINAL
        repo.get_scenario.return_value = scenario
        repo.list_runs.return_value = []
        provider_cls = MagicMock()
        console, _ = _fake_console()

        with patch.object(scenario_mod, "repository", repo), patch.object(
            scenario_mod, "get_session", side_effect=lambda: _session_cm()
        ), patch.object(
            scenario_mod, "DockerRootlessProvider", provider_cls
        ), patch.object(scenario_mod, "console", console):
            result = _perform_scenario_removal(str(sid), confirm=lambda msg: False)

        assert result is False
        provider_cls.assert_not_called()
        repo.delete_scenario.assert_not_called()

    def test_repl_remove_accepts_yes_flag(self):
        """`scenario remove <id> --yes` en el REPL: parsea el id, no exige prompt."""
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True, width=120)
        repl = FlexiPwnREPL(
            loop=MagicMock(),
            console=console,
            history_path=Path(os.devnull),
            prompter=lambda text: pytest.fail("no debería pedir confirmación con --yes"),
        )

        captured: dict = {}

        def fake_remove(scenario_id, confirm):
            captured["id"] = scenario_id
            captured["confirmed"] = confirm("¿borrar?")

        with patch(
            "flexipwn.layer4.cli.scenario._perform_scenario_removal", fake_remove
        ):
            repl.dispatch_line(
                "scenario remove 292e5d62-ca7b-4b67-bb4a-8dde4a7627a8 --yes"
            )

        assert captured["id"] == "292e5d62-ca7b-4b67-bb4a-8dde4a7627a8"
        assert captured["confirmed"] is True


class TestResetAll:
    def _patches(self, repo, provider_cls, console):
        return (
            patch("flexipwn.layer4.cli.daemon.require_daemon"),
            patch.object(cleanup_mod, "repository", repo),
            patch.object(cleanup_mod, "get_session", side_effect=lambda: _session_cm()),
            patch.object(cleanup_mod, "DockerRootlessProvider", provider_cls),
            patch.object(cleanup_mod, "FlexiPwnConfig", MagicMock()),
            patch.object(cleanup_mod, "console", console),
        )

    def test_scenario_mode_wipes_keeps_participants(self):
        runs = [SimpleNamespace(id=uuid.uuid4(), env_id="run-1", status="completed")]
        repo = MagicMock()
        repo.TERMINAL_STATUSES = _TERMINAL
        repo.list_runs.return_value = runs
        repo.list_scenarios.return_value = [SimpleNamespace(id=uuid.uuid4())]
        repo.reset_all_keep_participants.return_value = {
            "events": 0, "targets": 0, "runs": 1, "scenarios": 1,
        }
        provider = MagicMock()
        provider_cls = MagicMock(return_value=provider)
        console, _ = _fake_console()

        p1, p2, p3, p4, p5, p6 = self._patches(repo, provider_cls, console)
        with p1, p2, p3, p4, p5, p6:
            result = _perform_reset_all(confirm=lambda msg: True, mode="scenario")

        assert result is True
        repo.set_run_status.assert_not_called()  # sin activos
        provider.cleanup_all.assert_called_once()
        repo.reset_all_keep_participants.assert_called_once()
        repo.reset_all_keep_scenarios.assert_not_called()
        repo.list_scenarios.assert_called_once()

    def test_participant_mode_wipes_keeps_scenarios(self):
        runs = [SimpleNamespace(id=uuid.uuid4(), env_id="run-1", status="completed")]
        repo = MagicMock()
        repo.TERMINAL_STATUSES = _TERMINAL
        repo.list_runs.return_value = runs
        repo.list_participants.return_value = [SimpleNamespace(id=uuid.uuid4())]
        repo.reset_all_keep_scenarios.return_value = {
            "events": 0, "targets": 0, "runs": 1, "participants": 1,
        }
        provider = MagicMock()
        provider_cls = MagicMock(return_value=provider)
        console, _ = _fake_console()

        p1, p2, p3, p4, p5, p6 = self._patches(repo, provider_cls, console)
        with p1, p2, p3, p4, p5, p6:
            result = _perform_reset_all(confirm=lambda msg: True, mode="participant")

        assert result is True
        repo.set_run_status.assert_not_called()
        provider.cleanup_all.assert_called_once()
        repo.reset_all_keep_scenarios.assert_called_once()
        repo.reset_all_keep_participants.assert_not_called()
        # En modo participant el aviso cuenta participantes, no escenarios.
        repo.list_participants.assert_called_once()
        repo.list_scenarios.assert_not_called()

    def test_marks_active_stopping_then_wipes(self):
        active = SimpleNamespace(id=uuid.uuid4(), env_id="run-A", status="running")
        repo = MagicMock()
        repo.TERMINAL_STATUSES = _TERMINAL
        # Snapshot inicial con 1 activo; tras marcar 'stopping', la espera relee
        # y ya está terminal → sale del bucle sin dormir.
        repo.list_runs.side_effect = [
            [active],
            [SimpleNamespace(id=active.id, env_id="run-A", status="stopped")],
        ]
        repo.list_scenarios.return_value = []
        repo.reset_all_keep_participants.return_value = {
            "events": 0, "targets": 0, "runs": 1, "scenarios": 0,
        }
        provider = MagicMock()
        provider_cls = MagicMock(return_value=provider)
        console, _ = _fake_console()

        p1, p2, p3, p4, p5, p6 = self._patches(repo, provider_cls, console)
        with p1, p2, p3, p4, p5, p6:
            result = _perform_reset_all(confirm=lambda msg: True, mode="scenario")

        assert result is True
        assert repo.set_run_status.call_count == 1
        _session_arg, run_id_arg, status_arg = repo.set_run_status.call_args.args
        assert run_id_arg == active.id
        assert status_arg == "stopping"
        provider.cleanup_all.assert_called_once()
        repo.reset_all_keep_participants.assert_called_once()

    def test_cancel_does_not_wipe(self):
        repo = MagicMock()
        repo.TERMINAL_STATUSES = _TERMINAL
        repo.list_runs.return_value = [
            SimpleNamespace(id=uuid.uuid4(), env_id="run-1", status="completed")
        ]
        repo.list_scenarios.return_value = []
        provider_cls = MagicMock()
        console, _ = _fake_console()

        p1, p2, p3, p4, p5, p6 = self._patches(repo, provider_cls, console)
        with p1, p2, p3, p4, p5, p6:
            result = _perform_reset_all(confirm=lambda msg: False, mode="scenario")

        assert result is False
        repo.reset_all_keep_participants.assert_not_called()
        provider_cls.assert_not_called()


class TestResetAllNonBypassable:
    """La confirmación destructiva no se puede saltar: ni la CLI ni el REPL
    aceptan un `--yes` que evite escribir BORRAR."""

    def test_cli_scenario_reset_all_has_no_yes_option(self):
        from flexipwn.layer4.cli.scenario import scenario_reset_all
        import inspect

        params = inspect.signature(scenario_reset_all).parameters
        assert "yes" not in params

    def test_cli_participant_reset_all_has_no_yes_option(self):
        from flexipwn.layer4.cli.participant import participant_reset_all
        import inspect

        params = inspect.signature(participant_reset_all).parameters
        assert "yes" not in params

    def test_repl_scenario_reset_all_yes_does_not_bypass(self):
        """Aun pasando --yes, el confirm sigue exigiendo BORRAR vía el prompter."""
        repl = FlexiPwnREPL(
            loop=MagicMock(),
            console=Console(file=StringIO(), force_terminal=False, no_color=True, width=120),
            history_path=Path(os.devnull),
            prompter=lambda text: "no",  # el educador NO escribe BORRAR
        )
        captured: dict = {}

        def fake_reset(confirm, *, mode):
            captured["mode"] = mode
            captured["confirmed"] = confirm("¿?")

        with patch("flexipwn.layer4.cli.cleanup._perform_reset_all", fake_reset):
            repl.dispatch_line("scenario reset-all --yes")

        assert captured["mode"] == "scenario"
        # --yes no saltó la confirmación: con prompter != "BORRAR" → False.
        assert captured["confirmed"] is False

    def test_repl_participant_reset_all_dispatches_with_borrar(self):
        repl = FlexiPwnREPL(
            loop=MagicMock(),
            console=Console(file=StringIO(), force_terminal=False, no_color=True, width=120),
            history_path=Path(os.devnull),
            prompter=lambda text: "BORRAR",
        )
        captured: dict = {}

        def fake_reset(confirm, *, mode):
            captured["mode"] = mode
            captured["confirmed"] = confirm("¿?")

        with patch("flexipwn.layer4.cli.cleanup._perform_reset_all", fake_reset):
            repl.dispatch_line("participant reset-all")

        assert captured["mode"] == "participant"
        assert captured["confirmed"] is True
