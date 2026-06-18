"""Tests del cálculo de tiempos de un run (Funcionalidad 3).

`compute_run_timing`, `format_duration` y `duration_between` son funciones puras
→ se testean directamente sin DB ni Docker.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from flexipwn.layer4.core.run_timing import (
    compute_run_timing,
    duration_between,
    format_duration,
)

START = datetime(2026, 6, 18, 10, 0, 0, tzinfo=UTC)


def _tgt(index, desc, matched, *, secs=None, reset_at=None):
    """TargetResult falso. ``secs`` = segundos desde START para matched_at."""
    return SimpleNamespace(
        target_index=index,
        description=desc,
        matched=matched,
        matched_at=(START + timedelta(seconds=secs)) if secs is not None else None,
        reset_at=reset_at,
    )


class TestFormatDuration:
    def test_seconds(self):
        assert format_duration(5) == "5s"

    def test_minutes(self):
        assert format_duration(83) == "1m 23s"

    def test_hours(self):
        assert format_duration(3725) == "1h 02m 05s"

    def test_none(self):
        assert format_duration(None) == "—"

    def test_negative_clamped(self):
        assert format_duration(-10) == "0s"


class TestDurationBetween:
    def test_finished(self):
        assert duration_between(START, START + timedelta(seconds=120)) == 120

    def test_running_uses_now(self):
        now = START + timedelta(seconds=200)
        assert duration_between(START, None, now) == 200

    def test_no_start(self):
        assert duration_between(None, START) is None

    def test_naive_is_treated_as_utc(self):
        naive_start = datetime(2026, 6, 18, 10, 0, 0)  # sin tzinfo
        assert duration_between(naive_start, START + timedelta(seconds=60)) == 60


class TestComputeRunTiming:
    def test_total_and_per_stage_in_order(self):
        targets = [
            _tgt(0, "A", True, secs=120),
            _tgt(1, "B", True, secs=300),
            _tgt(2, "C", False),
        ]
        finished = START + timedelta(seconds=300)
        t = compute_run_timing(START, finished, True, targets, now=finished)

        assert t.total_seconds == 300
        assert t.time_to_first_seconds == 120
        assert [m.target_index for m in t.milestones] == [0, 1]
        assert (t.milestones[0].since_start, t.milestones[0].delta_prev) == (120, 120)
        assert (t.milestones[1].since_start, t.milestones[1].delta_prev) == (300, 180)
        assert t.pending == ["C"]
        assert t.completed is True

    def test_chronological_order_when_objectives_solved_out_of_yaml_order(self):
        # El objetivo 0 (YAML) se cumple DESPUÉS del 1 → el orden cronológico
        # manda y el delta se mide contra el hito real anterior.
        targets = [
            _tgt(0, "A", True, secs=300),
            _tgt(1, "B", True, secs=120),
        ]
        t = compute_run_timing(START, START + timedelta(seconds=300), True, targets)
        assert [m.target_index for m in t.milestones] == [1, 0]
        assert t.milestones[0].delta_prev == 120  # B contra START
        assert t.milestones[1].delta_prev == 180  # A contra B (300-120)

    def test_running_uses_elapsed_not_total(self):
        targets = [_tgt(0, "A", True, secs=60), _tgt(1, "B", False)]
        now = START + timedelta(seconds=200)
        t = compute_run_timing(START, None, False, targets, now=now)
        assert t.total_seconds is None
        assert t.elapsed_seconds == 200
        assert t.pending == ["B"]

    def test_ignores_previous_attempts(self):
        # Un target de un intento anterior (reset_at != None) no cuenta.
        old = _tgt(0, "vieja", True, secs=10, reset_at=START + timedelta(seconds=50))
        cur = _tgt(0, "actual", True, secs=120)
        t = compute_run_timing(START, None, False, [old, cur], now=START + timedelta(seconds=130))
        assert [m.description for m in t.milestones] == ["actual"]
        assert t.pending == []

    def test_no_started_at(self):
        t = compute_run_timing(None, None, False, [_tgt(0, "A", False)])
        assert t.started_at is None
        assert t.elapsed_seconds is None
        assert t.time_to_first_seconds is None
