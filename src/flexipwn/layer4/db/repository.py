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
from flexipwn.layer3.schema import ScenarioConfig, iter_leaf_targets, load_scenario


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


def delete_scenario(session: Session, scenario_id: str | uuid.UUID) -> None:
    """Borra la definición de un escenario.

    Asume que sus runs ya fueron eliminados (no hay cascade en los modelos):
    el comando `scenario remove` borra primero los runs terminales con
    `delete_run` y recién después llama aquí.
    """
    scenario = get_scenario(session, scenario_id)
    if scenario is not None:
        session.delete(scenario)
        session.commit()


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


def get_active_run_for_pair(
    session: Session,
    scenario_id: uuid.UUID,
    participant_id: uuid.UUID,
) -> ExerciseRun | None:
    """Run activo (no terminal) para un par escenario+participante, si existe.

    Permite rechazar un segundo run del mismo par ANTES de crear contenedores.
    El índice parcial uq_active_run solo bloquea status='running', pero aquí
    consideramos todos los estados activos para no dejar entornos a medio
    aprovisionar ni mensajes confusos.
    """
    return session.exec(
        select(ExerciseRun)
        .where(ExerciseRun.scenario_id == scenario_id)
        .where(ExerciseRun.participant_id == participant_id)
        .where(
            ExerciseRun.status.in_(("pending", "running", "stopping", "resetting"))  # type: ignore[attr-defined]
        )
    ).first()


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


def _delete_all_run_activity(session: Session) -> dict[str, int]:
    """Borra toda la actividad de runs (RunEvent, TargetResult, ExerciseRun)
    SIN commitear. Base común de los dos reset-all del laboratorio; cada uno
    completa la transacción tras borrar también escenarios o participantes.
    """
    events = list(session.exec(select(RunEvent)).all())
    targets = list(session.exec(select(TargetResult)).all())
    runs = list(session.exec(select(ExerciseRun)).all())
    for row in (*events, *targets, *runs):
        session.delete(row)
    return {"events": len(events), "targets": len(targets), "runs": len(runs)}


def reset_all_keep_participants(session: Session) -> dict[str, int]:
    """Wipe total conservando participantes — `scenario reset-all` (decisión 1.B).

    Borra RunEvent, TargetResult, ExerciseRun y Scenario; NO toca Participant.
    El teardown de los contenedores Docker NO ocurre aquí: lo hace el daemon (al
    marcar los runs activos como 'stopping') más un barrido final idempotente
    de `provider.cleanup_all()`. Devuelve conteos de lo borrado para el reporte.
    """
    counts = _delete_all_run_activity(session)
    scenarios = list(session.exec(select(Scenario)).all())
    for scenario in scenarios:
        session.delete(scenario)
    session.commit()
    counts["scenarios"] = len(scenarios)
    return counts


def reset_all_keep_scenarios(session: Session) -> dict[str, int]:
    """Wipe total conservando escenarios — `participant reset-all` (1.5).

    Espejo de `reset_all_keep_participants`: borra RunEvent, TargetResult,
    ExerciseRun y Participant; NO toca Scenario. Mismo teardown mediado por el
    daemon + barrido final. Devuelve conteos de lo borrado para el reporte.
    """
    counts = _delete_all_run_activity(session)
    participants = list(session.exec(select(Participant)).all())
    for participant in participants:
        session.delete(participant)
    session.commit()
    counts["participants"] = len(participants)
    return counts


# ---------------------------------------------------------------------------
# TargetResult
# ---------------------------------------------------------------------------


def _iter_leaf_results(targets):
    """Hojas del árbol de resultados del motor, en DFS (descendiendo and/or/not).

    Espeja exactamente a `iter_leaf_targets` sobre la config: como ambos árboles
    tienen la misma forma, ambas iteraciones emiten las hojas en el mismo orden.
    Esa correspondencia posicional es lo que hace robusto el matcheo por índice
    secuencial (sin necesidad de un path jerárquico en la DB).
    """
    for t in targets:
        if t.children:
            yield from _iter_leaf_results(t.children)
        else:
            yield t


def bulk_create_target_results(
    session: Session, run_id: uuid.UUID, scenario_config: ScenarioConfig
) -> list[TargetResult]:
    """Persiste una fila por HOJA del escenario (no por target de primer nivel).

    Antes solo se guardaban los targets de primer nivel: con una raíz and/or eso
    dejaba una única fila (el nodo lógico) y los pasos intermedios reales nunca
    se persistían. Ahora se aplana el árbol con `iter_leaf_targets` y cada hoja
    recibe un `target_index` secuencial global (0..N) en orden DFS.
    """
    results = []
    for i, leaf in enumerate(iter_leaf_targets(scenario_config.targets)):
        tr = TargetResult(
            run_id=run_id,
            target_index=i,
            target_type=leaf.type,
            description=leaf.description,
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

    # Mismo aplanado DFS que en bulk_create → la posición i de la hoja del motor
    # corresponde a la fila con target_index == i.
    for i, et in enumerate(_iter_leaf_results(engine_result.targets)):
        db_t = db_by_index.get(i)
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


# ---------------------------------------------------------------------------
# Dashboard + feed (vista del educador para muchos entornos simultáneos)
#
# Dos vistas, ambas leídas de la DB (no del buffer en memoria del
# NotificationSink):
#   - Dashboard: estado actual por entorno (ExerciseRun + conteo TargetResult).
#   - Feed: hitos cronológicos "objetivo cumplido" (TargetResult.matched_at),
#     que es el equivalente persistente de las notificaciones TARGET_MATCHED.
# `run_events` queda como stream crudo por-entorno para `run watch`.
# ---------------------------------------------------------------------------

# Estados "vivos" que el educador quiere vigilar en el dashboard/feed.
ACTIVE_STATUSES = ("pending", "running", "stopping", "resetting")


def _is_finished_today(run: ExerciseRun, today) -> bool:
    return run.finished_at is not None and run.finished_at.date() == today


def dashboard_rows(session: Session, *, include_finished: bool = False) -> list[dict]:
    """Una fila por entorno con su estado agregado.

    Por defecto solo entornos activos; con ``include_finished`` agrega los que
    terminaron hoy (status terminal con finished_at del día).
    """
    today = _now().date()
    rows = list(
        session.exec(
            select(ExerciseRun, Scenario, Participant)
            .join(Scenario, Scenario.id == ExerciseRun.scenario_id)
            .join(Participant, Participant.id == ExerciseRun.participant_id)
        ).all()
    )
    out: list[dict] = []
    for run, scenario, participant in rows:
        is_active = run.status in ACTIVE_STATUSES
        if not is_active and not (include_finished and _is_finished_today(run, today)):
            continue
        # Targets del intento actual (reset_at None).
        current = [t for t in get_target_results(session, run.id) if t.reset_at is None]
        total = len(current)
        matched = [t for t in current if t.matched]
        last = max(
            matched,
            key=lambda t: t.matched_at or datetime.min.replace(tzinfo=UTC),
            default=None,
        )
        out.append(
            {
                "env_id": run.env_id,
                "scenario_title": scenario.title,
                "participant_username": participant.username,
                "status": run.status,
                "matched": len(matched),
                "total": total,
                "progress": run.progress,
                "last_desc": last.description if last else None,
                "last_at": last.matched_at if last else None,
                "started_at": run.started_at,
                "finished_at": run.finished_at,
            }
        )
    # Activos primero, luego por progreso descendente.
    out.sort(
        key=lambda r: (
            r["status"] not in ACTIVE_STATUSES,
            -(r["matched"] / r["total"] if r["total"] else 0.0),
        )
    )
    return out


def feed_milestones(
    session: Session,
    *,
    all_history: bool = False,
    limit: int | None = 40,
) -> list[dict]:
    """Registro cronológico de hitos cruzando entornos.

    Es un LOG persistente, agnóstico al estado del run: un hito que ocurrió
    sigue en el feed aunque el run ya haya terminado (no se filtra por status).
    Dos tipos de entrada (campo ``kind``):
      - ``"target"``: una hoja del escenario que se cumplió (TargetResult.matched).
      - ``"scenario_completed"``: el run completó el escenario (ExerciseRun
        terminal 'completed' con finished_at) — equivale al viejo print
        '✓ ESCENARIO COMPLETADO', ahora persistente y dentro del feed.

    Por defecto solo entradas de HOY (para no crecer sin límite en pantalla);
    ``all_history`` devuelve todo. Retorna las ``limit`` más recientes (None =
    todas), del más viejo al más nuevo.
    """
    today = _now().date()
    items: list[dict] = []

    # 1) Hitos de objetivos (hojas matcheadas del intento actual).
    target_rows = list(
        session.exec(
            select(TargetResult, ExerciseRun, Participant)
            .join(ExerciseRun, ExerciseRun.id == TargetResult.run_id)
            .join(Participant, Participant.id == ExerciseRun.participant_id)
            .where(TargetResult.matched.is_(True))
            .where(TargetResult.reset_at.is_(None))
        ).all()
    )
    for target, run, participant in target_rows:
        at = target.matched_at
        if not all_history and (at is None or at.date() != today):
            continue
        items.append(
            {
                "kind": "target",
                "at": at,
                "env_id": run.env_id,
                "participant_username": participant.username,
                "description": target.description,
            }
        )

    # 2) Escenarios completados (entrada propia del feed).
    completed_rows = list(
        session.exec(
            select(ExerciseRun, Participant)
            .join(Participant, Participant.id == ExerciseRun.participant_id)
            .where(ExerciseRun.status == "completed")
        ).all()
    )
    for run, participant in completed_rows:
        at = run.finished_at
        if at is None:
            continue
        if not all_history and at.date() != today:
            continue
        items.append(
            {
                "kind": "scenario_completed",
                "at": at,
                "env_id": run.env_id,
                "participant_username": participant.username,
                "description": "ESCENARIO COMPLETADO",
            }
        )

    items.sort(key=lambda i: i["at"] or datetime.min.replace(tzinfo=UTC))
    if limit is not None:
        items = items[-limit:]
    return items


def count_new_milestones(session: Session, since: datetime) -> int:
    """Cuántas novedades hay después de ``since`` (base del badge del prompt).

    Cuenta hitos de objetivos + escenarios completados, agnóstico al estado del
    run (alineado con el feed). Cualquier cosa que entre al feed bumpea el badge.
    """
    target_count = len(
        session.exec(
            select(TargetResult.id)
            .where(TargetResult.matched.is_(True))
            .where(TargetResult.reset_at.is_(None))
            .where(TargetResult.matched_at.is_not(None))
            .where(TargetResult.matched_at > since)
        ).all()
    )
    completed_count = len(
        session.exec(
            select(ExerciseRun.id)
            .where(ExerciseRun.status == "completed")
            .where(ExerciseRun.finished_at.is_not(None))
            .where(ExerciseRun.finished_at > since)
        ).all()
    )
    return target_count + completed_count


def count_active_envs(session: Session) -> int:
    return len(
        session.exec(
            select(ExerciseRun.id).where(
                ExerciseRun.status.in_(ACTIVE_STATUSES)
            )
        ).all()
    )
