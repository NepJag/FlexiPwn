"""
Tests unitarios de Capa 3 — motor de evaluación.
Sin Docker, sin archivos reales. Todos los MonitorEvent se construyen directamente.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from flexipwn.layer2.events import MonitorEvent
from flexipwn.layer3.engine import EvaluationEngine, EvaluationResult
from flexipwn.layer3.schema import (
    EnvironmentConfig,
    ScenarioConfig,
    TargetConfig,
)
from flexipwn.layer3.targets.filesystem import (
    FileCreatedEvaluator,
    FileExistsEvaluator,
    FileModifiedEvaluator,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ENV_CFG = EnvironmentConfig(image="debian:12")
_NOW = datetime(2025, 10, 15, 14, 32, 1, tzinfo=timezone.utc)


def _event(
    event_type: str,
    monitor_type: str = "filesystem",
    details: dict | None = None,
) -> MonitorEvent:
    return MonitorEvent(
        timestamp=_NOW,
        monitor_type=monitor_type,  # type: ignore[arg-type]
        event_type=event_type,
        env_id="run-abc123",
        participant_id="student-a3f2c1",
        scenario_id="scenario-uuid",
        details=details or {},
    )


def _target(type_: str, **kwargs) -> TargetConfig:
    return TargetConfig(type=type_, description=f"target {type_}", **kwargs)


def _scenario(targets: list[TargetConfig], condition: str = "all") -> ScenarioConfig:
    return ScenarioConfig(
        title="Test",
        description="Test scenario",
        author="tester",
        level="beginner",
        category="pwning",
        environment=_ENV_CFG,
        targets=targets,
        condition=condition,  # type: ignore[arg-type]
    )


def _engine(
    targets: list[TargetConfig],
    condition: str = "all",
    callback=None,
) -> EvaluationEngine:
    cb = callback or MagicMock()
    return EvaluationEngine(
        scenario=_scenario(targets, condition),
        scenario_id="scenario-uuid",
        participant_id="student-a3f2c1",
        env_id="run-abc123",
        on_update=cb,
    )


# ---------------------------------------------------------------------------
# Tests de schema
# ---------------------------------------------------------------------------


def test_schema_loads_valid_yaml():
    data = {
        "title": "Privesc via sudo",
        "description": "Consigue root via sudo vim.",
        "author": "admin",
        "level": "beginner",
        "category": "pwning",
        "environment": {"image": "debian:12"},
        "targets": [
            {"type": "file_created", "description": "Flag creada", "path": "/root/pwned.txt"}
        ],
        "condition": "all",
    }
    scenario = ScenarioConfig.model_validate(data)
    assert scenario.title == "Privesc via sudo"
    assert scenario.condition == "all"
    assert len(scenario.targets) == 1
    assert scenario.targets[0].path == "/root/pwned.txt"


def test_schema_rejects_missing_path_in_file_created():
    with pytest.raises(ValidationError):
        TargetConfig(type="file_created", description="sin path")


def test_schema_rejects_empty_targets():
    with pytest.raises(ValidationError):
        ScenarioConfig(
            title="X",
            description="X",
            author="X",
            level="beginner",
            category="pwning",
            environment=_ENV_CFG,
            targets=[],
            condition="all",
        )


def test_schema_rejects_invalid_level():
    with pytest.raises(ValidationError):
        ScenarioConfig(
            title="X",
            description="X",
            author="X",
            level="expert",  # type: ignore[arg-type]
            category="pwning",
            environment=_ENV_CFG,
            targets=[_target("file_created", path="/root/x")],
            condition="all",
        )


# ---------------------------------------------------------------------------
# Tests de evaluadores
# ---------------------------------------------------------------------------


def test_file_created_matches_exact_path():
    ev = FileCreatedEvaluator(_target("file_created", path="/root/pwned.txt"))
    event = _event("file_created", details={"path": "/root/pwned.txt", "kind": 1})
    assert ev.matches(event) is True


def test_file_created_no_match_wrong_event_type():
    ev = FileCreatedEvaluator(_target("file_created", path="/root/pwned.txt"))
    event = _event("file_modified", details={"path": "/root/pwned.txt", "kind": 0})
    assert ev.matches(event) is False


def test_file_created_matches_directory_with_pattern():
    ev = FileCreatedEvaluator(_target("file_created", path="/root/", pattern="*.txt"))
    event = _event("file_created", details={"path": "/root/test.txt", "kind": 1})
    assert ev.matches(event) is True


def test_file_created_no_match_pattern_mismatch():
    ev = FileCreatedEvaluator(_target("file_created", path="/root/", pattern="*.txt"))
    event = _event("file_created", details={"path": "/root/test.log", "kind": 1})
    assert ev.matches(event) is False


def test_file_modified_matches():
    ev = FileModifiedEvaluator(_target("file_modified", path="/etc/passwd"))
    event = _event("file_modified", details={"path": "/etc/passwd", "kind": 0})
    assert ev.matches(event) is True


def test_file_exists_matches_with_content():
    ev = FileExistsEvaluator(
        _target("file_exists", path="/root/flag", contains="hacked")
    )
    event = _event(
        "file_exists",
        details={"path": "/root/flag", "content": "hacked"},
    )
    assert ev.matches(event) is True


def test_file_exists_no_match_content_missing():
    ev = FileExistsEvaluator(
        _target("file_exists", path="/root/flag", contains="hacked")
    )
    event = _event(
        "file_exists",
        details={"path": "/root/flag", "content": None},
    )
    assert ev.matches(event) is False


# ---------------------------------------------------------------------------
# Tests del motor
# ---------------------------------------------------------------------------


def test_engine_any_completes_on_first_match():
    t1 = _target("file_created", path="/root/flag1.txt")
    t2 = _target("file_created", path="/root/flag2.txt")
    cb = MagicMock()
    engine = _engine([t1, t2], condition="any", callback=cb)

    engine.process_event(_event("file_created", details={"path": "/root/flag1.txt"}))

    result: EvaluationResult = cb.call_args[0][0]
    assert result.completed is True


def test_engine_all_requires_all_targets():
    t1 = _target("file_created", path="/root/flag1.txt")
    t2 = _target("file_created", path="/root/flag2.txt")
    cb = MagicMock()
    engine = _engine([t1, t2], condition="all", callback=cb)

    engine.process_event(_event("file_created", details={"path": "/root/flag1.txt"}))
    result_after_first: EvaluationResult = cb.call_args[0][0]
    assert result_after_first.completed is False

    engine.process_event(_event("file_created", details={"path": "/root/flag2.txt"}))
    result_after_second: EvaluationResult = cb.call_args[0][0]
    assert result_after_second.completed is True


def test_engine_callback_called_on_change():
    t1 = _target("file_created", path="/root/pwned.txt")
    cb = MagicMock()
    engine = _engine([t1], callback=cb)

    engine.process_event(_event("file_created", details={"path": "/root/pwned.txt"}))

    cb.assert_called_once()


def test_engine_callback_not_called_if_no_change():
    t1 = _target("file_created", path="/root/pwned.txt")
    cb = MagicMock()
    engine = _engine([t1], callback=cb)

    # Evento que no matchea ningún target
    engine.process_event(_event("file_modified", details={"path": "/etc/shadow"}))

    cb.assert_not_called()


def test_engine_matched_is_irreversible():
    t1 = _target("file_exists", path="/root/flag", contains="hacked")
    cb = MagicMock()
    engine = _engine([t1], callback=cb)

    # Matchea: content presente
    engine.process_event(
        _event("file_exists", details={"path": "/root/flag", "content": "hacked"})
    )
    assert engine.current_result().targets[0].matched is True

    # Evento "contradictorio": mismo archivo, content=None
    engine.process_event(
        _event("file_exists", details={"path": "/root/flag", "content": None})
    )
    # Sigue matched — los logros no se revierten
    assert engine.current_result().targets[0].matched is True


def test_engine_progress_calculation():
    t1 = _target("file_created", path="/root/flag1.txt")
    t2 = _target("file_created", path="/root/flag2.txt")
    engine = _engine([t1, t2])

    engine.process_event(_event("file_created", details={"path": "/root/flag1.txt"}))

    assert engine.current_result().progress == 0.5


def test_engine_reset_clears_state():
    t1 = _target("file_created", path="/root/pwned.txt")
    engine = _engine([t1])

    engine.process_event(_event("file_created", details={"path": "/root/pwned.txt"}))
    assert engine.current_result().targets[0].matched is True

    engine.reset()

    result = engine.current_result()
    assert result.targets[0].matched is False
    assert result.progress == 0.0
    assert result.completed is False
