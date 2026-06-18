"""Estadísticas de tiempo de un run.

Todo se deriva de timestamps que ya persistimos — no requiere cambios de schema:
``ExerciseRun.started_at`` / ``finished_at`` y ``TargetResult.matched_at`` (por
hoja, del intento actual ``reset_at is None``).

`compute_run_timing` es una función pura y determinista (dado ``now``): los
consumidores (run show, dashboard) solo formatean su salida. Los hitos se
ordenan por ``matched_at`` — orden cronológico real — porque el estudiante puede
cumplir los objetivos en cualquier orden, así que un "delta entre el objetivo 1
y 2 del YAML" sería engañoso; el delta se calcula contra el hito anterior real.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


def _aware(dt: datetime | None) -> datetime | None:
    """Normaliza a tz-aware UTC. SQLite puede devolver datetimes naive aunque la
    columna sea ``DateTime(timezone=True)``; esto evita errores al restar
    aware - naive."""
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def format_duration(seconds: float | None) -> str:
    """Segundos → texto compacto: ``5s`` / ``1m 23s`` / ``1h 02m 05s``.
    ``None`` → ``—`` (objetivo no alcanzado / sin dato)."""
    if seconds is None:
        return "—"
    total = max(0, int(round(seconds)))
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m:02d}m {s:02d}s"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def duration_between(
    start: datetime | None,
    end: datetime | None,
    now: datetime | None = None,
) -> float | None:
    """Segundos entre ``start`` y ``end``; si ``end`` es None usa ``now`` (run en
    curso → tiempo transcurrido). None si no hay ``start``."""
    start = _aware(start)
    if start is None:
        return None
    end = _aware(end) or _aware(now) or datetime.now(UTC)
    return (end - start).total_seconds()


@dataclass
class Milestone:
    target_index: int
    description: str
    matched_at: datetime
    since_start: float | None   # segundos desde started_at
    delta_prev: float | None    # segundos desde el hito anterior (o desde start)


@dataclass
class RunTiming:
    started_at: datetime | None
    finished_at: datetime | None
    completed: bool
    elapsed_seconds: float | None        # (finished_at or now) - started_at
    total_seconds: float | None          # solo si finished_at (tiempo final)
    time_to_first_seconds: float | None
    milestones: list[Milestone]
    pending: list[str]                   # descripciones de objetivos sin alcanzar


def compute_run_timing(
    started_at: datetime | None,
    finished_at: datetime | None,
    completed: bool,
    targets,
    *,
    now: datetime | None = None,
) -> RunTiming:
    """Línea de tiempo de UN run (intento actual).

    ``targets`` = TargetResults del run; se consideran solo las hojas del intento
    actual (``reset_at is None``). Los hitos cumplidos se ordenan por
    ``matched_at``; ``delta_prev`` del primero es contra ``started_at``.
    """
    started = _aware(started_at)
    finished = _aware(finished_at)
    now = _aware(now) or datetime.now(UTC)

    current = [t for t in targets if getattr(t, "reset_at", None) is None]
    matched = sorted(
        (t for t in current if t.matched and t.matched_at is not None),
        key=lambda t: _aware(t.matched_at),
    )

    milestones: list[Milestone] = []
    prev = started
    for t in matched:
        matched_at = _aware(t.matched_at)
        since = (matched_at - started).total_seconds() if started else None
        delta = (matched_at - prev).total_seconds() if prev else None
        milestones.append(
            Milestone(
                target_index=t.target_index,
                description=t.description,
                matched_at=matched_at,
                since_start=since,
                delta_prev=delta,
            )
        )
        prev = matched_at

    pending = [t.description for t in current if not t.matched]
    elapsed = ((finished or now) - started).total_seconds() if started else None
    total = (finished - started).total_seconds() if (finished and started) else None
    time_to_first = milestones[0].since_start if milestones else None

    return RunTiming(
        started_at=started,
        finished_at=finished,
        completed=completed,
        elapsed_seconds=elapsed,
        total_seconds=total,
        time_to_first_seconds=time_to_first,
        milestones=milestones,
        pending=pending,
    )
