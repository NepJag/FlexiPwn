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

from flexipwn.db import models as _models  # noqa: F401
from flexipwn.db.models import ExerciseRun, Participant, RunEvent, Scenario, TargetResult
from flexipwn.db.session import init_db
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
        from flexipwn.db import repository
        with Session(engine) as s:
            participant, plaintext = repository.create_participant(s)

        assert participant.username.startswith("student-")
        assert len(plaintext) > 0
        # La contraseña en claro no está en el hash
        assert plaintext not in participant.password_hash

    def test_verify_password(self, engine):
        from flexipwn.db import repository
        with Session(engine) as s:
            participant, plaintext = repository.create_participant(s)
            assert repository.verify_participant_password(participant, plaintext)
            assert not repository.verify_participant_password(participant, "wrong-password")


# ---------------------------------------------------------------------------
# RunEvent
# ---------------------------------------------------------------------------


class TestRunEvent:
    def test_append_and_list_run_events(self, engine):
        from flexipwn.db import repository

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
