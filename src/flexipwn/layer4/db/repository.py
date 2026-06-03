from __future__ import annotations

import json
import secrets
import uuid
from datetime import UTC, datetime
from pathlib import Path

import bcrypt
from sqlmodel import Session, select

from flexipwn.layer4.db.models import (
    ExerciseRun,
    Participant,
    RunEvent,
    Scenario,
    TargetResult,
)
from flexipwn.layer2.events import MonitorEvent
from flexipwn.layer3.engine import EvaluationResult
from flexipwn.layer3.schema import ScenarioConfig, load_scenario


def _now() -> datetime:
    return datetime.now(UTC)


# Estados terminales de un run: el daemon ya no los procesa y tienen finished_at.
TERMINAL_STATUSES = ("completed", "failed", "timeout", "stopped")


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------


def create_scenario(session: Session, yaml_path: str) -> Scenario:
    path = Path(yaml_path).resolve()
    yaml_content = path.read_text()
    config: ScenarioConfig = load_scenario(path)

    scenario = Scenario(
        yaml_path=str(path),
        yaml_content=yaml_content,
        title=config.title,
        description=config.description,
        author=config.author,
        level=config.level,
        category=config.category,
        image=config.environment.image,
        attacker_image=config.environment.attacker_image,
        timeout_seconds=config.timeout_seconds,
    )
    session.add(scenario)
    session.commit()
    session.refresh(scenario)
    return scenario


def list_scenarios(session: Session) -> list[Scenario]:
    return list(session.exec(select(Scenario)).all())


def get_scenario(session: Session, scenario_id: str | uuid.UUID) -> Scenario | None:
    sid = uuid.UUID(str(scenario_id)) if not isinstance(scenario_id, uuid.UUID) else scenario_id
    return session.get(Scenario, sid)


def parse_scenario_config(scenario: Scenario) -> ScenarioConfig:
    import yaml
    raw = yaml.safe_load(scenario.yaml_content)
    return ScenarioConfig.model_validate(raw)


# ---------------------------------------------------------------------------
# Participant
# ---------------------------------------------------------------------------


def create_participant(session: Session) -> tuple[Participant, str]:
    username = f"student-{secrets.token_hex(3)}"
    plaintext = secrets.token_urlsafe(12)
    password_hash = bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt()).decode()
    participant = Participant(username=username, password_hash=password_hash)
    session.add(participant)
    session.commit()
    session.refresh(participant)
    return participant, plaintext


def reset_participant_password(session: Session, username: str) -> str:
    participant = get_participant_by_username(session, username)
    if participant is None:
        raise ValueError(f"Participante no encontrado: {username!r}")
    plaintext = secrets.token_urlsafe(12)
    participant.password_hash = bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt()).decode()
    session.add(participant)
    session.commit()
    return plaintext


def list_participants(session: Session) -> list[Participant]:
    return list(session.exec(select(Participant)).all())


def get_participant_by_username(session: Session, username: str) -> Participant | None:
    return session.exec(select(Participant).where(Participant.username == username)).first()


def verify_participant_password(participant: Participant, plaintext: str) -> bool:
    return bcrypt.checkpw(plaintext.encode(), participant.password_hash.encode())


# ---------------------------------------------------------------------------
# ExerciseRun
# ---------------------------------------------------------------------------


def create_run(
    session: Session,
    scenario_id: uuid.UUID,
    participant_id: uuid.UUID,
    env_id: str,
    attacker_ssh_port: int | None = None,
) -> ExerciseRun:
    run = ExerciseRun(
        scenario_id=scenario_id,
        participant_id=participant_id,
        env_id=env_id,
        status="pending",
        attacker_ssh_port=attacker_ssh_port,
    )
    session.add(run)
    session.commit()
    session.refresh(run)
    return run


def mark_run_started(
    session: Session,
    run_id: uuid.UUID,
    attacker_ssh_port: int | None = None,
) -> ExerciseRun:
    run = session.get(ExerciseRun, run_id)
    if run is None:
        raise ValueError(f"Run no encontrado: {run_id}")
    run.status = "running"
    run.started_at = _now()
    if attacker_ssh_port is not None:
        run.attacker_ssh_port = attacker_ssh_port
    session.add(run)
    session.commit()
    session.refresh(run)
    return run


def set_run_status(
    session: Session,
    run_id: uuid.UUID,
    status: str,
    message: str | None = None,
) -> ExerciseRun:
    run = session.get(ExerciseRun, run_id)
    if run is None:
        raise ValueError(f"Run no encontrado: {run_id}")
    run.status = status
    if message is not None:
        run.daemon_message = message
    if status in TERMINAL_STATUSES and run.finished_at is None:
        run.finished_at = _now()
    session.add(run)
    session.commit()
    session.refresh(run)
    return run


def set_attacker_ssh_credentials(
    session: Session,
    run_id: uuid.UUID,
    username: str,
    password: str,
    port: int,
) -> ExerciseRun:
    run = session.get(ExerciseRun, run_id)
    if run is None:
        raise ValueError(f"Run no encontrado: {run_id}")
    run.attacker_ssh_username = username
    run.attacker_ssh_password = password
    run.attacker_ssh_port = port
    session.add(run)
    session.commit()
    session.refresh(run)
    return run


def set_reset_payload(session: Session, run_id: uuid.UUID, payload_json: str) -> None:
    run = session.get(ExerciseRun, run_id)
    if run is None:
        raise ValueError(f"Run no encontrado: {run_id}")
    run.reset_payload = payload_json
    session.add(run)
    session.commit()


def clear_reset_payload(session: Session, run_id: uuid.UUID) -> None:
    run = session.get(ExerciseRun, run_id)
    if run is None:
        return
    run.reset_payload = None
    session.add(run)
    session.commit()


def get_runs_needing_action(session: Session) -> list[ExerciseRun]:
    """Runs en estados que el daemon debe procesar."""
    return list(
        session.exec(
            select(ExerciseRun).where(
                ExerciseRun.status.in_(("running", "stopping", "resetting"))  # type: ignore[attr-defined]
            )
        ).all()
    )


def list_runs_with_context(
    session: Session,
    scenario_id: uuid.UUID | None = None,
    participant_id: uuid.UUID | None = None,
) -> list[dict]:
    stmt = (
        select(ExerciseRun, Scenario, Participant)
        .join(Scenario, Scenario.id == ExerciseRun.scenario_id)
        .join(Participant, Participant.id == ExerciseRun.participant_id)
    )
    if scenario_id is not None:
        stmt = stmt.where(ExerciseRun.scenario_id == scenario_id)
    if participant_id is not None:
        stmt = stmt.where(ExerciseRun.participant_id == participant_id)
    rows = list(session.exec(stmt).all())
    out: list[dict] = []
    for run, scenario, participant in rows:
        out.append(
            {
                "env_id": run.env_id,
                "scenario_title": scenario.title,
                "participant_username": participant.username,
                "status": run.status,
                "progress": run.progress,
                "started_at": run.started_at,
                "attacker_ssh_port": run.attacker_ssh_port,
                "run_id": run.id,
            }
        )
    return out


def get_active_runs_by_participant(
    session: Session, participant_id: uuid.UUID
) -> list[ExerciseRun]:
    return list(
        session.exec(
            select(ExerciseRun)
            .where(ExerciseRun.participant_id == participant_id)
            .where(
                ExerciseRun.status.in_(("pending", "running", "stopping", "resetting"))  # type: ignore[attr-defined]
            )
        ).all()
    )


def delete_participant(session: Session, participant_id: uuid.UUID) -> None:
    participant = session.get(Participant, participant_id)
    if participant is None:
        return
    session.delete(participant)
    session.commit()


def mark_run_finished(session: Session, run_id: uuid.UUID, status: str) -> ExerciseRun:
    run = session.get(ExerciseRun, run_id)
    if run is None:
        raise ValueError(f"Run no encontrado: {run_id}")
    run.status = status
    run.finished_at = _now()
    session.add(run)
    session.commit()
    session.refresh(run)
    return run


def update_run_progress(session: Session, run_id: uuid.UUID, progress: float) -> None:
    run = session.get(ExerciseRun, run_id)
    if run is None:
        return
    run.progress = progress
    session.add(run)
    session.commit()


def list_runs(
    session: Session,
    scenario_id: uuid.UUID | None = None,
    participant_id: uuid.UUID | None = None,
) -> list[ExerciseRun]:
    stmt = select(ExerciseRun)
    if scenario_id is not None:
        stmt = stmt.where(ExerciseRun.scenario_id == scenario_id)
    if participant_id is not None:
        stmt = stmt.where(ExerciseRun.participant_id == participant_id)
    return list(session.exec(stmt).all())


def get_run_by_env_id(session: Session, env_id: str) -> ExerciseRun | None:
    return session.exec(select(ExerciseRun).where(ExerciseRun.env_id == env_id)).first()


def delete_run(session: Session, run_id: uuid.UUID) -> None:
    """Borra un run y sus filas hijas (no hay cascade en los modelos)."""
    for target in get_target_results(session, run_id):
        session.delete(target)
    for event in list_run_events(session, run_id):
        session.delete(event)
    run = session.get(ExerciseRun, run_id)
    if run is not None:
        session.delete(run)
    session.commit()


# ---------------------------------------------------------------------------
# TargetResult
# ---------------------------------------------------------------------------


def _collect_leaf_targets(targets, parent_index=""):
    leaves = []
    for i, t in enumerate(targets):
        if t.type in ("and", "or", "not"):
            sub = _collect_leaf_targets(t.targets or [], parent_index=f"{parent_index}{i}.")
            leaves.extend(sub)
        else:
            leaves.append((i, t))
    return leaves


def bulk_create_target_results(
    session: Session, run_id: uuid.UUID, scenario_config: ScenarioConfig
) -> list[TargetResult]:
    results = []
    for i, target in enumerate(scenario_config.targets):
        tr = TargetResult(
            run_id=run_id,
            target_index=i,
            target_type=target.type,
            description=target.description,
        )
        session.add(tr)
        results.append(tr)
    session.commit()
    return results


def update_target_results_from_engine(
    session: Session, run_id: uuid.UUID, engine_result: EvaluationResult
) -> None:
    db_targets = list(
        session.exec(select(TargetResult).where(TargetResult.run_id == run_id)).all()
    )
    db_by_index = {t.target_index: t for t in db_targets if t.reset_at is None}

    for et in engine_result.targets:
        db_t = db_by_index.get(et.target_index)
        if db_t is None:
            continue
        if et.matched and not db_t.matched:
            db_t.matched = True
            db_t.matched_at = et.matched_at
            if et.trigger_event is not None:
                db_t.trigger_event = et.trigger_event.model_dump_json()
            session.add(db_t)
    session.commit()


def mark_targets_reset(session: Session, run_id: uuid.UUID) -> None:
    targets = list(
        session.exec(
            select(TargetResult).where(
                TargetResult.run_id == run_id,
                TargetResult.reset_at.is_(None),  # type: ignore[attr-defined]
            )
        ).all()
    )
    now = _now()
    for t in targets:
        t.reset_at = now
        session.add(t)
    session.commit()


def get_target_results(session: Session, run_id: uuid.UUID) -> list[TargetResult]:
    return list(session.exec(select(TargetResult).where(TargetResult.run_id == run_id)).all())


def get_target_results_by_run(session: Session, run_id: uuid.UUID) -> list[TargetResult]:
    """TargetResults del run, ordenados por reset_at ascendente con NULLs al final."""
    rows = list(
        session.exec(
            select(TargetResult).where(TargetResult.run_id == run_id)
        ).all()
    )
    return sorted(
        rows,
        key=lambda r: (
            r.reset_at is None,
            r.reset_at if r.reset_at is not None else datetime.max.replace(tzinfo=UTC),
            r.target_index,
        ),
    )


# ---------------------------------------------------------------------------
# RunEvent
# ---------------------------------------------------------------------------


def append_run_event(session: Session, run_id: uuid.UUID, event: MonitorEvent) -> RunEvent:
    re = RunEvent(
        run_id=run_id,
        timestamp=event.timestamp,
        monitor_type=event.monitor_type,
        event_type=event.event_type,
        details_json=json.dumps(event.details),
    )
    session.add(re)
    session.commit()
    return re


def list_run_events(
    session: Session, run_id: uuid.UUID, since: datetime | None = None
) -> list[RunEvent]:
    stmt = select(RunEvent).where(RunEvent.run_id == run_id)
    if since is not None:
        stmt = stmt.where(RunEvent.timestamp > since)
    stmt = stmt.order_by(RunEvent.timestamp)  # type: ignore[arg-type]
    return list(session.exec(stmt).all())
