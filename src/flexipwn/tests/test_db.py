"""
Tests unitarios de la capa DB (sin Docker, sin archivos de escenario reales).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, create_engine, text

from flexipwn.layer4.db import models as _models  # noqa: F401
from flexipwn.layer4.db.models import ExerciseRun, Participant, RunEvent, Scenario, TargetResult
from flexipwn.layer4.db.session import init_db
from flexipwn.layer2.events import MonitorEvent


def _now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def engine(tmp_path):
    db_path = tmp_path / "test.db"
    eng = create_engine(f"sqlite:///{db_path}", echo=False)
    init_db(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine):
    with Session(engine) as s:
        yield s


# ---------------------------------------------------------------------------
# Índice parcial
# ---------------------------------------------------------------------------


class TestPartialIndex:
    def test_index_exists(self, engine):
        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='index' AND name='uq_active_run'")
            ).fetchone()
        assert result is not None, "El índice uq_active_run debe existir"

    def test_blocks_two_running_same_pair(self, engine):
        """No pueden coexistir dos runs en estado 'running' para el mismo par."""
        with Session(engine) as s:
            scenario = Scenario(
                yaml_path="/tmp/x.yaml",
                yaml_content="title: x",
                title="x", description="", author="a",
                level="beginner", category="pwning", image="img:latest",
            )
            participant = Participant(
                username="student-aabbcc",
                password_hash="fakehash",
            )
            s.add(scenario)
            s.add(participant)
            s.commit()
            s.refresh(scenario)
            s.refresh(participant)

            r1 = ExerciseRun(
                scenario_id=scenario.id,
                participant_id=participant.id,
                env_id="run-00000001",
                status="running",
            )
            s.add(r1)
            s.commit()

            r2 = ExerciseRun(
                scenario_id=scenario.id,
                participant_id=participant.id,
                env_id="run-00000002",
                status="running",
            )
            s.add(r2)
            with pytest.raises((IntegrityError, Exception)):
                s.commit()

    def test_allows_multiple_completed(self, engine):
        """Múltiples runs completados con el mismo par son permitidos."""
        with Session(engine) as s:
            scenario = Scenario(
                yaml_path="/tmp/y.yaml",
                yaml_content="title: y",
                title="y", description="", author="a",
                level="beginner", category="pwning", image="img:latest",
            )
            participant = Participant(
                username="student-ddeeff",
                password_hash="fakehash",
            )
            s.add(scenario)
            s.add(participant)
            s.commit()
            s.refresh(scenario)
            s.refresh(participant)

            for i in range(3):
                r = ExerciseRun(
                    scenario_id=scenario.id,
                    participant_id=participant.id,
                    env_id=f"run-comp{i:08d}",
                    status="completed",
                )
                s.add(r)
            s.commit()


# ---------------------------------------------------------------------------
# Scenario CRUD
# ---------------------------------------------------------------------------


class TestScenarioCRUD:
    def test_scenario_persisted_fields(self, session):
        scenario = Scenario(
            yaml_path="/path/privesc.yaml",
            yaml_content="title: Privesc\ndescription: test\nauthor: dev\nlevel: beginner\ncategory: pwning\nenvironment:\n  image: vuln:latest\ntargets: []\ncondition: all",
            title="Privesc",
            description="test",
            author="dev",
            level="beginner",
            category="pwning",
            image="vuln:latest",
            timeout_seconds=900,
        )
        session.add(scenario)
        session.commit()
        session.refresh(scenario)

        assert isinstance(scenario.id, uuid.UUID)
        assert scenario.yaml_path == "/path/privesc.yaml"
        assert "Privesc" in scenario.yaml_content
        assert scenario.timeout_seconds == 900


# ---------------------------------------------------------------------------
# Participant CRUD
# ---------------------------------------------------------------------------


class TestParticipantCRUD:
    def test_username_unique(self, session):
        p1 = Participant(username="student-abc123", password_hash="h1")
        p2 = Participant(username="student-abc123", password_hash="h2")
        session.add(p1)
        session.commit()
        session.add(p2)
        with pytest.raises(Exception):
            session.commit()

    def test_create_participant_via_repository(self, engine):
        from flexipwn.layer4.db import repository
        with Session(engine) as s:
            participant, plaintext = repository.create_participant(s)

        assert participant.username.startswith("student-")
        assert len(plaintext) > 0
        # La contraseña en claro no está en el hash
        assert plaintext not in participant.password_hash

    def test_verify_password(self, engine):
        from flexipwn.layer4.db import repository
        with Session(engine) as s:
            participant, plaintext = repository.create_participant(s)
            assert repository.verify_participant_password(participant, plaintext)
            assert not repository.verify_participant_password(participant, "wrong-password")


# ---------------------------------------------------------------------------
# RunEvent
# ---------------------------------------------------------------------------


class TestRunEvent:
    def test_append_and_list_run_events(self, engine):
        from flexipwn.layer4.db import repository

        with Session(engine) as s:
            scenario = Scenario(
                yaml_path="/tmp/ev.yaml",
                yaml_content="t",
                title="ev", description="", author="a",
                level="beginner", category="pwning", image="img:latest",
            )
            participant = Participant(username="student-ev1234", password_hash="h")
            s.add(scenario)
            s.add(participant)
            s.commit()
            s.refresh(scenario)
            s.refresh(participant)

            run = ExerciseRun(
                scenario_id=scenario.id,
                participant_id=participant.id,
                env_id="run-evtest01",
                status="running",
            )
            s.add(run)
            s.commit()
            s.refresh(run)

            event = MonitorEvent(
                timestamp=_now(),
                monitor_type="filesystem",
                event_type="file_created",
                env_id="run-evtest01",
                participant_id="student-ev1234",
                scenario_id=str(scenario.id),
                details={"path": "/tmp/pwned.txt"},
            )
            repository.append_run_event(s, run.id, event)

            events = repository.list_run_events(s, run.id)
            assert len(events) == 1
            assert events[0].monitor_type == "filesystem"
            assert events[0].event_type == "file_created"


# ---------------------------------------------------------------------------
# Daemon-related fields and repository helpers
# ---------------------------------------------------------------------------


def _seed_run(session, env_id: str = "run-test0001") -> tuple[ExerciseRun, Scenario, Participant]:
    scenario = Scenario(
        yaml_path="/tmp/x.yaml", yaml_content="t",
        title="X", description="", author="a", level="beginner", category="pwning",
        image="img:latest", attacker_image="flexipwn-attacker",
    )
    participant = Participant(username=f"student-{env_id[-6:]}", password_hash="h")
    session.add(scenario)
    session.add(participant)
    session.commit()
    session.refresh(scenario)
    session.refresh(participant)

    run = ExerciseRun(
        scenario_id=scenario.id, participant_id=participant.id,
        env_id=env_id, status="running",
    )
    session.add(run)
    session.commit()
    session.refresh(run)
    return run, scenario, participant


class TestNewRunFields:
    def test_attacker_ssh_fields_persist(self, session):
        run, _, _ = _seed_run(session)
        run.attacker_ssh_port = 2200
        run.attacker_ssh_username = "student-test"
        run.attacker_ssh_password = "secret-pass"
        run.reset_payload = '{"foo": 1}'
        run.daemon_message = "hello"
        session.add(run)
        session.commit()
        session.refresh(run)
        assert run.attacker_ssh_port == 2200
        assert run.attacker_ssh_username == "student-test"
        assert run.attacker_ssh_password == "secret-pass"
        assert run.reset_payload == '{"foo": 1}'
        assert run.daemon_message == "hello"


class TestRepositoryHelpers:
    def test_set_attacker_ssh_credentials(self, engine):
        from flexipwn.layer4.db import repository
        with Session(engine) as s:
            run, _, _ = _seed_run(s, env_id="run-cred0001")
            repository.set_attacker_ssh_credentials(s, run.id, "student-x", "pwd123", 2201)
            s.refresh(run)
            assert run.attacker_ssh_username == "student-x"
            assert run.attacker_ssh_password == "pwd123"
            assert run.attacker_ssh_port == 2201

    def test_set_run_status_finalizes_finished_at(self, engine):
        from flexipwn.layer4.db import repository
        with Session(engine) as s:
            run, _, _ = _seed_run(s, env_id="run-stat0001")
            assert run.finished_at is None
            repository.set_run_status(s, run.id, "completed")
            s.refresh(run)
            assert run.status == "completed"
            assert run.finished_at is not None

    def test_set_run_status_message(self, engine):
        from flexipwn.layer4.db import repository
        with Session(engine) as s:
            run, _, _ = _seed_run(s, env_id="run-msg00001")
            repository.set_run_status(s, run.id, "failed", message="boom")
            s.refresh(run)
            assert run.daemon_message == "boom"

    def test_get_runs_needing_action_filters_by_status(self, engine):
        from flexipwn.layer4.db import repository
        with Session(engine) as s:
            run_running, _, _ = _seed_run(s, env_id="run-need0001")
            run_done, _, _ = _seed_run(s, env_id="run-need0002")
            run_done.status = "completed"
            s.add(run_done)
            s.commit()

            runs = repository.get_runs_needing_action(s)
            ids = {r.id for r in runs}
            assert run_running.id in ids
            assert run_done.id not in ids

    def test_set_and_clear_reset_payload(self, engine):
        from flexipwn.layer4.db import repository
        with Session(engine) as s:
            run, _, _ = _seed_run(s, env_id="run-payld001")
            repository.set_reset_payload(s, run.id, '{"a": 1}')
            s.refresh(run)
            assert run.reset_payload == '{"a": 1}'
            repository.clear_reset_payload(s, run.id)
            s.refresh(run)
            assert run.reset_payload is None

    def test_list_runs_with_context(self, engine):
        from flexipwn.layer4.db import repository
        with Session(engine) as s:
            run, scenario, participant = _seed_run(s, env_id="run-ctx00001")
            run.attacker_ssh_port = 2210
            s.add(run)
            s.commit()
            rows = repository.list_runs_with_context(s)
            assert len(rows) == 1
            row = rows[0]
            assert row["env_id"] == "run-ctx00001"
            assert row["scenario_title"] == scenario.title
            assert row["participant_username"] == participant.username
            assert row["attacker_ssh_port"] == 2210

    def test_get_target_results_by_run_orders_with_nulls_last(self, engine):
        from flexipwn.layer4.db import repository
        with Session(engine) as s:
            run, _, _ = _seed_run(s, env_id="run-trord001")
            now = _now()
            previous = TargetResult(
                run_id=run.id, target_index=0, target_type="t",
                description="prev", reset_at=now,
            )
            current = TargetResult(
                run_id=run.id, target_index=0, target_type="t",
                description="curr", reset_at=None,
            )
            s.add(previous)
            s.add(current)
            s.commit()

            results = repository.get_target_results_by_run(s, run.id)
            assert len(results) == 2
            assert results[0].reset_at is not None  # previo va primero
            assert results[1].reset_at is None      # actual al final

    def test_active_runs_and_delete_participant(self, engine):
        from flexipwn.layer4.db import repository
        with Session(engine) as s:
            run, _, participant = _seed_run(s, env_id="run-prem0001")
            active = repository.get_active_runs_by_participant(s, participant.id)
            assert any(r.id == run.id for r in active)

            # No se puede eliminar mientras hay activos: el caller debe
            # bloquear; el repository simplemente borra. Aquí marcamos el
            # run como completed primero.
            run.status = "completed"
            s.add(run)
            s.commit()

            assert repository.get_active_runs_by_participant(s, participant.id) == []
            repository.delete_participant(s, participant.id)
            from flexipwn.layer4.db.models import Participant as P
            assert s.get(P, participant.id) is None
