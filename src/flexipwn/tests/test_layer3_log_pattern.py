"""
Tests de LogPatternEvaluator (Capa 3) — puramente unitarios, sin I/O.
"""
from datetime import datetime, timezone

import pytest

from flexipwn.layer2.events import MonitorEvent
from flexipwn.layer3.schema import TargetConfig
from flexipwn.layer3.targets.log import LogPatternEvaluator


def _make_event(details: dict) -> MonitorEvent:
    return MonitorEvent(
        timestamp=datetime.now(timezone.utc),
        monitor_type="log",
        event_type="log_entry",
        env_id="env-test",
        participant_id="player",
        scenario_id="test",
        details=details,
    )


def _make_evaluator(field_matches: dict) -> LogPatternEvaluator:
    config = TargetConfig(
        type="log_pattern",
        description="test",
        field_matches=field_matches,
    )
    return LogPatternEvaluator(config)


class TestLogPatternEvaluator:

    def test_log_pattern_matches_json_field(self):
        """Campo JSON parseado matchea exactamente."""
        evaluator = _make_evaluator({"event_type": "authentication_success"})
        event = _make_event({"parsed": {"event_type": "authentication_success"}})
        assert evaluator.matches(event) is True

    def test_log_pattern_matches_raw_line_regex(self):
        """raw_line con regex parcial matchea correctamente."""
        evaluator = _make_evaluator({"raw_line": "SELECT.*sensitive_data"})
        event = _make_event({"raw_line": "2024-01-01 Query SELECT * FROM sensitive_data WHERE id=1"})
        assert evaluator.matches(event) is True

    def test_log_pattern_no_match_missing_field(self):
        """Campo especificado en field_matches no existe en el evento → no matchea."""
        evaluator = _make_evaluator({"event_type": "authentication_success"})
        # El evento solo tiene raw_line, no parsed
        event = _make_event({"raw_line": "some plain log line"})
        assert evaluator.matches(event) is False

    def test_log_pattern_regex_partial_match(self):
        """re.search() encuentra el patrón en cualquier parte del valor."""
        evaluator = _make_evaluator({"raw_line": "OR.*1.*=.*1"})
        event = _make_event({"raw_line": "SELECT * FROM users WHERE username='' OR '1'='1' --"})
        assert evaluator.matches(event) is True

    def test_log_pattern_invalid_regex_no_crash(self):
        """Regex inválida → no matchea, no lanza excepción."""
        evaluator = _make_evaluator({"raw_line": "[invalid"})
        event = _make_event({"raw_line": "any log line"})
        assert evaluator.matches(event) is False

    def test_log_pattern_ignores_non_log_entry_events(self):
        """Eventos que no son log_entry no deben matchear."""
        config = TargetConfig(
            type="log_pattern",
            description="test",
            field_matches={"raw_line": ".*"},
        )
        evaluator = LogPatternEvaluator(config)
        event = MonitorEvent(
            timestamp=datetime.now(timezone.utc),
            monitor_type="filesystem",
            event_type="file_created",
            env_id="env-test",
            participant_id="player",
            scenario_id="test",
            details={"path": "/tmp/foo"},
        )
        assert evaluator.matches(event) is False

    def test_log_pattern_all_conditions_must_match(self):
        """AND implícito: si uno de los field_matches no matchea, retorna False."""
        evaluator = _make_evaluator({
            "event_type": "authentication_success",
            "username": "admin",
        })
        # event_type matchea pero username no
        event = _make_event({"parsed": {"event_type": "authentication_success", "username": "student"}})
        assert evaluator.matches(event) is False

        # Ambos matchean
        event2 = _make_event({"parsed": {"event_type": "authentication_success", "username": "admin"}})
        assert evaluator.matches(event2) is True
