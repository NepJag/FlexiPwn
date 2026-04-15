from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timezone

from docker.errors import APIError, NotFound

from flexipwn.layer1.provider import EnvironmentNotFoundError, EnvironmentProvider
from flexipwn.layer2.events import MonitorEvent

logger = logging.getLogger(__name__)

OnEventCallback = Callable[[MonitorEvent], None]
OnStoppedCallback = Callable[[str], None]

_KIND_TO_EVENT_TYPE: dict[int, str] = {
    0: "file_modified",
    1: "file_created",
    2: "file_deleted",
}


class FilesystemMonitor:
    """
    Monitorea cambios en el filesystem del contenedor usando container.diff().

    Principio de pasividad: no ejecuta nada dentro del contenedor,
    no modifica su estado, no monta volúmenes.

    Diseñado para ser invocado vía _poll() por MonitorOrchestrator.
    El intervalo de polling y la gestión del timeout son responsabilidad
    del orquestador, no del monitor.
    """

    def __init__(
        self,
        provider: EnvironmentProvider,
        env_id: str,
        scenario_id: str,
        participant_id: str,
        on_event: OnEventCallback,
        on_stopped: OnStoppedCallback | None = None,
    ) -> None:
        self._provider = provider
        self._env_id = env_id
        self._scenario_id = scenario_id
        self._participant_id = participant_id
        self._on_event = on_event
        self._on_stopped = on_stopped

        # _seen_paths: path → kind del último evento emitido.
        # kind=-1 es el centinela de baseline: paths que existían antes del
        # ejercicio y nunca deben reportarse.
        self._seen_paths: dict[str, int] = {}
        baseline: set[str] = getattr(provider, "_baselines", {}).get(env_id, set())
        for path in baseline:
            self._seen_paths[path] = -1

    def _poll(self) -> None:
        """
        Una iteración:
        1. Obtener diff actual via provider.get_filesystem_diff(env_id)
        2. Comparar contra _seen_paths (paths ya reportados)
        3. Emitir MonitorEvent para paths nuevos o con kind cambiado
        4. Actualizar _seen_paths

        Si el contenedor se ha detenido o desaparecido, llama on_stopped y retorna.
        """
        try:
            diff = self._provider.get_filesystem_diff(self._env_id)
        except (NotFound, EnvironmentNotFoundError):
            logger.info("Contenedor %s desaparecido, terminando monitor de filesystem.", self._env_id)
            if self._on_stopped:
                self._on_stopped(self._env_id)
            return
        except APIError as exc:
            if "is not running" in str(exc).lower():
                logger.info("Contenedor %s detenido, terminando monitor de filesystem.", self._env_id)
                if self._on_stopped:
                    self._on_stopped(self._env_id)
                return
            raise

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
