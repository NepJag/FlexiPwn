from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime

from rich.console import Console

from flexipwn.layer2.orchestrator import MonitorOrchestrator
from flexipwn.layer3.engine import EvaluationResult, TargetResult as EngineTargetResult

logger = logging.getLogger(__name__)


@dataclass
class _Slot:
    orchestrator: MonitorOrchestrator
    run_id: uuid.UUID
    started_at: datetime
    timeout_seconds: int
    on_timeout: Callable[[str], None] | None = None  # receives env_id


class SuperMonitor:
    """
    Supervisor singleton que gestiona múltiples entornos de monitoreo en paralelo.

    Corre un thread supervisor que llama poll_once() de cada orchestrator
    vía un ThreadPoolExecutor. También detecta timeouts por entorno.
    """

    def __init__(
        self,
        poll_interval: float = 2.0,
        max_workers: int = 16,
    ) -> None:
        self._poll_interval = poll_interval
        self._max_workers = max_workers
        self._slots: dict[str, _Slot] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._executor: ThreadPoolExecutor | None = None

    def start(self) -> None:
        self._stop_event.clear()
        self._executor = ThreadPoolExecutor(max_workers=self._max_workers)
        self._thread = threading.Thread(target=self._loop, daemon=True, name="super-monitor")
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
        if self._executor is not None:
            self._executor.shutdown(wait=False)

    def add_environment(
        self,
        env_id: str,
        orchestrator: MonitorOrchestrator,
        run_id: uuid.UUID,
        started_at: datetime,
        timeout_seconds: int,
        on_timeout: Callable[[str], None] | None = None,
    ) -> None:
        # Defensa contra started_at naive (DB legacy o callers despistados):
        # asumimos UTC y promovemos a aware para no romper la resta en _loop.
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=UTC)
        with self._lock:
            self._slots[env_id] = _Slot(
                orchestrator=orchestrator,
                run_id=run_id,
                started_at=started_at,
                timeout_seconds=timeout_seconds,
                on_timeout=on_timeout,
            )

    def remove_environment(self, env_id: str) -> None:
        with self._lock:
            self._slots.pop(env_id, None)

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            cycle_start = time.monotonic()

            with self._lock:
                snapshot = dict(self._slots)

            if snapshot and self._executor is not None:
                futures = {
                    self._executor.submit(slot.orchestrator.poll_once): env_id
                    for env_id, slot in snapshot.items()
                }
                for future in as_completed(futures):
                    env_id = futures[future]
                    try:
                        future.result()
                    except Exception:
                        logger.exception("Error en poll_once para entorno %s", env_id)

            # Chequear timeouts
            now = datetime.now(UTC)
            for env_id, slot in snapshot.items():
                elapsed = (now - slot.started_at).total_seconds()
                if elapsed >= slot.timeout_seconds:
                    logger.info("Timeout alcanzado para entorno %s", env_id)
                    slot.orchestrator.stop()
                    self.remove_environment(env_id)
                    if slot.on_timeout is not None:
                        try:
                            slot.on_timeout(env_id)
                        except Exception:
                            logger.exception("Error en on_timeout para entorno %s", env_id)

            elapsed_total = time.monotonic() - cycle_start
            sleep_time = max(0.0, self._poll_interval - elapsed_total)
            self._stop_event.wait(timeout=sleep_time)


_instance: SuperMonitor | None = None
_instance_lock = threading.Lock()


def get_super_monitor(poll_interval: float = 2.0, max_workers: int = 16) -> SuperMonitor:
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = SuperMonitor(poll_interval=poll_interval, max_workers=max_workers)
            _instance.start()
    return _instance


def _count_leaves(targets: list[EngineTargetResult]) -> tuple[int, int]:
    matched = 0
    total = 0
    for t in targets:
        if t.children:
            sub_m, sub_t = _count_leaves(t.children)
            matched += sub_m
            total += sub_t
        else:
            total += 1
            if t.matched:
                matched += 1
    return matched, total


class RichProgressPrinter:
    """Imprime con Rich el progreso de targets de un EvaluationEngine.

    Cada instancia de FlexiPwn (típicamente el daemon) crea uno y registra
    un callback por entorno vía build_callback(env_id). El callback se pasa
    como `on_update` al EvaluationEngine.
    """

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()
        self._announced: dict[str, set[int]] = {}
        self._lock = threading.Lock()

    def build_callback(self, env_id: str) -> Callable[[EvaluationResult], None]:
        def _on_update(result: EvaluationResult) -> None:
            with self._lock:
                announced = self._announced.setdefault(env_id, set())
                fresh: list[EngineTargetResult] = []
                self._collect_fresh(result.targets, announced, fresh)
            for t in fresh:
                self._console.print(
                    f"[green][{env_id}][/green] ✓ {t.description}"
                )
            matched, total = _count_leaves(result.targets)
            pct = int(result.progress * 100)
            self._console.print(
                f"[{env_id}] Progreso: {matched}/{total} ({pct}%)"
            )

        return _on_update

    def _collect_fresh(
        self,
        targets: list[EngineTargetResult],
        announced: set[int],
        out: list[EngineTargetResult],
    ) -> None:
        for t in targets:
            if t.children:
                self._collect_fresh(t.children, announced, out)
                continue
            if (
                t.matched
                and t.matched_at is not None
                and t.target_index not in announced
            ):
                announced.add(t.target_index)
                out.append(t)

    def reset(self, env_id: str) -> None:
        with self._lock:
            self._announced.pop(env_id, None)
