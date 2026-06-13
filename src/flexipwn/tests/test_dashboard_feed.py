"""Tests de las queries de dashboard y feed del educador (sin Docker)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlmodel import Session, create_engine

from flexipwn.layer3.engine import EvaluationResult
from flexipwn.layer3.engine import TargetResult as EngineTarget
from flexipwn.layer3.schema import TargetConfig
from flexipwn.layer4.db import repository
from flexipwn.layer4.db.models import (
    ExerciseRun,
    Participant,
    Scenario,
    TargetResult,
)
from flexipwn.layer4.db.session import init_db


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


def _scenario(s: Session, title: str = "Esc") -> Scenario:
    sc = Scenario(
        yaml_path="/tmp/x.yaml", yaml_content="title: x", title=title,
        description="", author="a", level="beginner", category="pwning",
        image="img:latest",
    )
    s.add(sc)
    s.commit()
    s.refresh(sc)
    return sc


def _participant(s: Session, username: str) -> Participant:
    p = Participant(username=username, password_hash="h")
    s.add(p)
    s.commit()
    s.refresh(p)
    return p


def _run(s: Session, sc, p, env_id: str, status: str, **kw) -> ExerciseRun:
    r = ExerciseRun(
        scenario_id=sc.id, participant_id=p.id, env_id=env_id, status=status, **kw
    )
    s.add(r)
    s.commit()
    s.refresh(r)
    return r


def _target(s: Session, run, idx, desc, *, matched=False, matched_at=None, reset_at=None):
    t = TargetResult(
        run_id=run.id, target_index=idx, target_type="file_created",
        description=desc, matched=matched, matched_at=matched_at, reset_at=reset_at,
    )
    s.add(t)
    s.commit()
    return t


# ---------------------------------------------------------------------------
# dashboard_rows
# ---------------------------------------------------------------------------


def test_dashboard_solo_activos_por_defecto(session):
    sc = _scenario(session)
    p1 = _participant(session, "alu1")
    p2 = _participant(session, "alu2")
    activo = _run(session, sc, p1, "run-active01", "running")
    _run(session, sc, p2, "run-done0001", "completed", finished_at=datetime.now(UTC))

    rows = repository.dashboard_rows(session)
    env_ids = {r["env_id"] for r in rows}
    assert env_ids == {"run-active01"}
    assert rows[0]["participant_username"] == "alu1"
    assert activo.env_id in env_ids


def test_dashboard_all_incluye_terminados_hoy(session):
    sc = _scenario(session)
    p = _participant(session, "alu1")
    _run(session, sc, p, "run-active01", "running")
    _run(session, sc, p, "run-done0001", "completed", finished_at=datetime.now(UTC))

    rows = repository.dashboard_rows(session, include_finished=True)
    assert {r["env_id"] for r in rows} == {"run-active01", "run-done0001"}


def test_dashboard_cuenta_objetivos_y_ultimo_hito(session):
    sc = _scenario(session)
    p = _participant(session, "alu1")
    run = _run(session, sc, p, "run-aaaa0001", "running")
    t0 = datetime.now(UTC) - timedelta(minutes=5)
    t1 = datetime.now(UTC)
    _target(session, run, 0, "objetivo viejo", matched=True, matched_at=t0)
    _target(session, run, 1, "objetivo nuevo", matched=True, matched_at=t1)
    _target(session, run, 2, "pendiente")

    row = repository.dashboard_rows(session)[0]
    assert row["matched"] == 2
    assert row["total"] == 3
    assert row["last_desc"] == "objetivo nuevo"  # el de matched_at más reciente


def test_dashboard_ignora_targets_de_intentos_previos(session):
    sc = _scenario(session)
    p = _participant(session, "alu1")
    run = _run(session, sc, p, "run-aaaa0001", "running")
    # reset_at != None → intento previo, no cuenta en el dashboard actual.
    _target(session, run, 0, "viejo", matched=True, matched_at=datetime.now(UTC),
            reset_at=datetime.now(UTC))
    _target(session, run, 0, "actual")

    row = repository.dashboard_rows(session)[0]
    assert row["matched"] == 0
    assert row["total"] == 1


# ---------------------------------------------------------------------------
# feed_milestones / count_new_milestones / count_active_envs
# ---------------------------------------------------------------------------


def test_feed_ordena_cronologicamente_entre_entornos(session):
    sc = _scenario(session)
    pa = _participant(session, "alu1")
    pb = _participant(session, "alu2")
    ra = _run(session, sc, pa, "run-aaaa0001", "running")
    rb = _run(session, sc, pb, "run-bbbb0002", "running")
    base = datetime.now(UTC)
    _target(session, ra, 0, "A primero", matched=True, matched_at=base)
    _target(session, rb, 0, "B segundo", matched=True, matched_at=base + timedelta(seconds=10))
    _target(session, ra, 1, "A tercero", matched=True, matched_at=base + timedelta(seconds=20))

    feed = repository.feed_milestones(session)
    assert [i["description"] for i in feed] == ["A primero", "B segundo", "A tercero"]
    assert {i["env_id"] for i in feed} == {"run-aaaa0001", "run-bbbb0002"}


def test_feed_persiste_terminados_y_excluye_no_matcheados(session):
    # El feed es un LOG persistente: un hito de un run que ya terminó NO
    # desaparece (regresión del bug donde se "borraban" al completar).
    sc = _scenario(session)
    p1 = _participant(session, "alu1")
    p2 = _participant(session, "alu2")
    activo = _run(session, sc, p1, "run-aaaa0001", "running")
    term = _run(session, sc, p2, "run-bbbb0002", "completed", finished_at=datetime.now(UTC))
    _target(session, activo, 0, "visible", matched=True, matched_at=datetime.now(UTC))
    _target(session, activo, 1, "no matcheado")
    _target(session, term, 0, "de terminado", matched=True, matched_at=datetime.now(UTC))

    feed = repository.feed_milestones(session)
    descs = {i["description"] for i in feed}
    assert "visible" in descs
    assert "de terminado" in descs           # persiste pese a estar completado
    assert "no matcheado" not in descs
    # Y el completado entra como su propia entrada del feed.
    assert "scenario_completed" in {i["kind"] for i in feed}


def test_feed_incluye_entrada_escenario_completado(session):
    sc = _scenario(session)
    p = _participant(session, "alu1")
    _run(session, sc, p, "run-aaaa0001", "completed", finished_at=datetime.now(UTC))

    entries = [i for i in repository.feed_milestones(session)
               if i["kind"] == "scenario_completed"]
    assert len(entries) == 1
    assert entries[0]["env_id"] == "run-aaaa0001"
    assert entries[0]["participant_username"] == "alu1"


def test_count_new_milestones_cuenta_completados(session):
    sc = _scenario(session)
    p = _participant(session, "alu1")
    cursor = datetime.now(UTC) - timedelta(seconds=5)
    _run(session, sc, p, "run-aaaa0001", "completed", finished_at=datetime.now(UTC))
    # Sin hitos de target, el completado por sí solo bumpea el badge.
    assert repository.count_new_milestones(session, cursor) >= 1


# ---------------------------------------------------------------------------
# Persistencia de hojas en escenarios and/or (índice secuencial)
# ---------------------------------------------------------------------------


def _and_scenario():
    """Stand-in de ScenarioConfig: bulk_create solo accede a `.targets`."""
    leaf1 = TargetConfig(type="file_created", description="crear archivo", path="/root/x.txt")
    leaf2 = TargetConfig(type="process_running", description="shell root",
                         euid=0, cmd_contains="bash")
    root = TargetConfig(type="and", description="raíz and", targets=[leaf1, leaf2])
    return SimpleNamespace(targets=[root])


def test_bulk_create_persiste_hojas_no_la_raiz(session):
    sc = _scenario(session)
    p = _participant(session, "alu1")
    run = _run(session, sc, p, "run-aaaa0001", "running")
    rows = repository.bulk_create_target_results(session, run.id, _and_scenario())
    # 2 hojas, no 1 nodo `and`.
    assert len(rows) == 2
    descs = {r.description for r in repository.get_target_results(session, run.id)}
    assert descs == {"crear archivo", "shell root"}
    assert "raíz and" not in descs


def test_update_from_engine_marca_hoja_anidada(session):
    sc = _scenario(session)
    p = _participant(session, "alu1")
    run = _run(session, sc, p, "run-aaaa0001", "running")
    repository.bulk_create_target_results(session, run.id, _and_scenario())

    now = datetime.now(UTC)
    eleaf1 = EngineTarget(target_index=0, target_type="file_created",
                          description="crear archivo", matched=True, matched_at=now)
    eleaf2 = EngineTarget(target_index=1, target_type="process_running",
                          description="shell root", matched=False)
    eroot = EngineTarget(target_index=0, target_type="and", description="raíz and",
                         matched=False, children=[eleaf1, eleaf2])
    res = EvaluationResult(
        scenario_id="s", participant_id="p", env_id="run-aaaa0001",
        condition="all", targets=[eroot], completed=False, progress=0.5,
    )
    repository.update_target_results_from_engine(session, run.id, res)

    rows = {r.description: r for r in repository.get_target_results(session, run.id)}
    assert rows["crear archivo"].matched is True
    assert rows["shell root"].matched is False
    # El dashboard ahora reporta 1/2 (pasos intermedios), no 0/1 ni la raíz sola.
    drow = repository.dashboard_rows(session)[0]
    assert (drow["matched"], drow["total"]) == (1, 2)
    assert drow["last_desc"] == "crear archivo"


def test_count_new_milestones_respeta_cursor(session):
    sc = _scenario(session)
    p = _participant(session, "alu1")
    run = _run(session, sc, p, "run-aaaa0001", "running")
    cursor = datetime.now(UTC)
    _target(session, run, 0, "viejo", matched=True, matched_at=cursor - timedelta(seconds=30))
    _target(session, run, 1, "nuevo1", matched=True, matched_at=cursor + timedelta(seconds=10))
    _target(session, run, 2, "nuevo2", matched=True, matched_at=cursor + timedelta(seconds=20))

    assert repository.count_new_milestones(session, cursor) == 2


def test_count_active_envs(session):
    sc = _scenario(session)
    p1 = _participant(session, "alu1")
    p2 = _participant(session, "alu2")
    p3 = _participant(session, "alu3")
    _run(session, sc, p1, "run-aaaa0001", "running")
    _run(session, sc, p2, "run-bbbb0002", "pending")
    _run(session, sc, p3, "run-cccc0003", "completed", finished_at=datetime.now(UTC))

    assert repository.count_active_envs(session) == 2
