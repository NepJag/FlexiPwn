from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import datetime, timezone

from docker.errors import APIError, NotFound

from flexipwn.layer1.provider import EnvironmentNotFoundError, EnvironmentProvider
from flexipwn.layer2.events import MonitorEvent

logger = logging.getLogger(__name__)

OnEventCallback = Callable[[MonitorEvent], None]
OnStoppedCallback = Callable[[str], None]  # recibe env_id
OnTimeoutCallback = Callable[[], None]

_KIND_TO_EVENT_TYPE: dict[int, str] = {
    0: "file_modified",
    1: "file_created",
    2: "file_deleted",
}


class FilesystemMonitor:
    """
    Monitorea cambios en el filesystem del contenedor usando container.diff()
    con polling. Bloqueante: llama a run() y el proceso queda en el loop.

    Principio de pasividad: no ejecuta nada dentro del contenedor,
    no modifica su estado, no monta volúmenes.
    """

    def __init__(
        self,
        provider: EnvironmentProvider,
        env_id: str,
        scenario_id: str,
        participant_id: str,
        on_event: OnEventCallback,
        on_stopped: OnStoppedCallback | None = None,
        on_timeout: OnTimeoutCallback | None = None,
        poll_interval: float = 1.5,
        timeout_seconds: int | None = None,
    ) -> None:
        self._provider = provider
        self._env_id = env_id
        self._scenario_id = scenario_id
        self._participant_id = participant_id
        self._on_event = on_event
        self._on_stopped = on_stopped
        self._on_timeout = on_timeout
        self._poll_interval = poll_interval
        self._timeout_seconds = timeout_seconds
        self._running = False

        # _seen_paths: path → kind del último evento emitido.
        # kind=-1 es el centinela de baseline: paths que existían antes del
        # ejercicio y nunca deben reportarse.
        self._seen_paths: dict[str, int] = {}
        baseline: set[str] = getattr(provider, "_baselines", {}).get(env_id, set())
        for path in baseline:
            self._seen_paths[path] = -1

    # ------------------------------------------------------------------
    # Interfaz pública
    # ------------------------------------------------------------------

    def run(self) -> None:
        """
        Loop principal de monitoreo. Bloqueante.
        Termina cuando:
        - el contenedor se detiene o desaparece
        - se llama a stop()
        - KeyboardInterrupt
        """
        self._running = True
        _start = time.monotonic()
        try:
            while self._running:
                if self._timeout_seconds is not None:
                    if time.monotonic() - _start >= self._timeout_seconds:
                        logger.info("Timeout alcanzado para entorno %s.", self._env_id)
                        if self._on_timeout:
                            self._on_timeout()
                        return
                try:
                    self._poll()
                except (NotFound, EnvironmentNotFoundError):
                    logger.info("Contenedor %s desaparecido, terminando monitor.", self._env_id)
                    if self._on_stopped:
                        self._on_stopped(self._env_id)
                    return
                except APIError as exc:
                    if "is not running" in str(exc).lower():
                        logger.info("Contenedor %s detenido, terminando monitor.", self._env_id)
                        if self._on_stopped:
                            self._on_stopped(self._env_id)
                        return
                    raise
                if not self._running:
                    return
                time.sleep(self._poll_interval)
        except KeyboardInterrupt:
            pass

    def stop(self) -> None:
        """Señala al loop de run() que debe terminar tras el poll actual."""
        self._running = False

    # ------------------------------------------------------------------
    # Internos
    # ------------------------------------------------------------------

    def _poll(self) -> None:
        """
        Una iteración del loop:
        1. Obtener diff actual via provider.get_filesystem_diff(env_id)
        2. Comparar contra _seen_paths (paths ya reportados)
        3. Para cada path nuevo o con kind cambiado, emitir MonitorEvent
        4. Actualizar _seen_paths
        """
        diff = self._provider.get_filesystem_diff(self._env_id)
        for item in diff:
            kind: int = item["kind"]
            path: str = item["path"]
            prev_kind = self._seen_paths.get(path)

            if prev_kind is None:
                # Path nuevo, nunca visto → emitir
                self._emit_event(kind, path)
                self._seen_paths[path] = kind
            elif prev_kind == -1:
                # Path de baseline → jamás emitir, mantener centinela
                pass
            elif prev_kind != kind:
                # Kind cambió (ej: creado → modificado) → emitir
                self._emit_event(kind, path)
                self._seen_paths[path] = kind
            # else: mismo kind → sin cambio, no emitir

    def _emit_event(self, kind: int, path: str) -> None:
        """
        Construye y emite un MonitorEvent.
        kind: 0=modificado, 1=creado, 2=eliminado
        """
        event_type = _KIND_TO_EVENT_TYPE.get(kind, "file_modified")
        event = MonitorEvent(
            timestamp=datetime.now(timezone.utc),
            monitor_type="filesystem",
            event_type=event_type,
            env_id=self._env_id,
            participant_id=self._participant_id,
            scenario_id=self._scenario_id,
            details={"path": path, "kind": kind},
        )
        self._on_event(event)
