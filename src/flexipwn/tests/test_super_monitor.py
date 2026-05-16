"""
Tests unitarios del SuperMonitor (sin Docker).
"""
from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from flexipwn.core.super_monitor import SuperMonitor


def _now() -> datetime:
    return datetime.now(timezone.utc)


class _CountingOrchestrator:
    """Fake orchestrator que cuenta llamadas a poll_once."""

    def __init__(self):
        self.poll_count = 0
        self.lock = threading.Lock()

    def poll_once(self) -> None:
        with self.lock:
            self.poll_count += 1

    def stop(self) -> None:
        pass


class _RaisingOrchestrator:
    """Fake orchestrator cuyo poll_once siempre lanza."""

    def poll_once(self) -> None:
        raise RuntimeError("simulated failure")

    def stop(self) -> None:
        pass


class TestSuperMonitorPolling:
    def test_polls_all_registered_environments(self):
        sm = SuperMonitor(poll_interval=0.05, max_workers=4)
        sm.start()

        orcs = [_CountingOrchestrator() for _ in range(3)]
        for i, orc in enumerate(orcs):
            sm.add_environment(
                env_id=f"run-test{i:08d}",
                orchestrator=orc,
                run_id=uuid.uuid4(),
                started_at=_now(),
                timeout_seconds=3600,
            )

        time.sleep(0.3)
        sm.stop()

        for orc in orcs:
            assert orc.poll_count >= 3, f"Expected ≥3 polls, got {orc.poll_count}"

    def test_isolates_failures(self):
        """Un orchestrator que falla no mata el loop ni los demás."""
        sm = SuperMonitor(poll_interval=0.05, max_workers=4)
        sm.start()

        bad_orc = _RaisingOrchestrator()
        good_orc = _CountingOrchestrator()

        sm.add_environment(
            env_id="run-bad00000",
            orchestrator=bad_orc,
            run_id=uuid.uuid4(),
            started_at=_now(),
            timeout_seconds=3600,
        )
        sm.add_environment(
            env_id="run-good0000",
            orchestrator=good_orc,
            run_id=uuid.uuid4(),
            started_at=_now(),
            timeout_seconds=3600,
        )

        time.sleep(0.3)
        sm.stop()

        assert good_orc.poll_count >= 3

    def test_remove_environment_stops_polling(self):
        sm = SuperMonitor(poll_interval=0.05, max_workers=4)
        sm.start()

        orc = _CountingOrchestrator()
        env_id = "run-remove01"
        sm.add_environment(
            env_id=env_id,
            orchestrator=orc,
            run_id=uuid.uuid4(),
            started_at=_now(),
            timeout_seconds=3600,
        )
        time.sleep(0.15)
        count_before = orc.poll_count
        sm.remove_environment(env_id)
        time.sleep(0.2)
        count_after = orc.poll_count
        sm.stop()

        # Después de remove, puede haber 0 o 1 ciclos más pero no muchos
        assert count_after - count_before <= 2

    def test_timeout_triggers_callback(self):
        sm = SuperMonitor(poll_interval=0.05, max_workers=4)
        sm.start()

        orc = _CountingOrchestrator()
        timeout_called: list[str] = []

        def on_timeout(eid: str) -> None:
            timeout_called.append(eid)

        env_id = "run-timeout1"
        sm.add_environment(
            env_id=env_id,
            orchestrator=orc,
            run_id=uuid.uuid4(),
            started_at=datetime(2000, 1, 1, tzinfo=timezone.utc),  # muy en el pasado
            timeout_seconds=1,
            on_timeout=on_timeout,
        )

        time.sleep(0.3)
        sm.stop()

        assert env_id in timeout_called

    def test_timeout_removes_environment(self):
        sm = SuperMonitor(poll_interval=0.05, max_workers=4)
        sm.start()

        orc = _CountingOrchestrator()
        env_id = "run-timeout2"
        sm.add_environment(
            env_id=env_id,
            orchestrator=orc,
            run_id=uuid.uuid4(),
            started_at=datetime(2000, 1, 1, tzinfo=timezone.utc),
            timeout_seconds=1,
        )

        time.sleep(0.3)

        with sm._lock:
            assert env_id not in sm._slots

        sm.stop()
