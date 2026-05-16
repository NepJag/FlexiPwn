from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timezone

from flexipwn.layer1.provider import EnvironmentProvider, ProcessInfo
from flexipwn.layer2.events import MonitorEvent

logger = logging.getLogger(__name__)

OnEventCallback = Callable[[MonitorEvent], None]
OnStoppedCallback = Callable[[str], None]


class ProcessMonitor:
    """
    Monitorea procesos nuevos en el contenedor usando container.top().

    Principio de pasividad: no ejecuta nada dentro del contenedor.
    Usa container.top() vía EnvironmentProvider — completamente externo.

    Baseline: snapshot de procesos tomado en la primera llamada a _poll(),
    asegurando que el contenedor ya está estable (el baseline de startup
    ya ocurrió en create()). Solo se reportan procesos cuyo process_id
    no estaba en el baseline. El filtrado por euid u otras condiciones
    es responsabilidad de Capa 3.
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
        self._baseline: set[str] | None = None

    def _poll(self) -> None:
        """
        Una iteración:
        1. Obtener lista actual de procesos via provider.get_processes()
        2. Si es la primera llamada, inicializar _baseline y retornar
        3. Emitir process_spawned para procesos nuevos (no en baseline)
        """
        from docker.errors import APIError, NotFound

        from flexipwn.layer1.provider import EnvironmentNotFoundError

        try:
            processes = self._provider.get_processes(self._env_id)
        except (NotFound, EnvironmentNotFoundError):
            logger.info("Contenedor %s desaparecido, terminando monitor de procesos.", self._env_id)
            if self._on_stopped:
                self._on_stopped(self._env_id)
            return
        except APIError as exc:
            if "is not running" in str(exc).lower():
                logger.info("Contenedor %s detenido, terminando monitor de procesos.", self._env_id)
                if self._on_stopped:
                    self._on_stopped(self._env_id)
                return
            raise

        if self._baseline is None:
            self._baseline = {p.process_id for p in processes}
            logger.debug(
                "Baseline de procesos capturado: %d procesos en %s.",
                len(self._baseline),
                self._env_id,
            )
            return

        for process in processes:
            if process.process_id not in self._baseline:
                self._emit_event(process)
                self._baseline.add(process.process_id)

    def _emit_event(self, process: ProcessInfo) -> None:
        event = MonitorEvent(
            timestamp=datetime.now(timezone.utc),
            monitor_type="process",
            event_type="process_spawned",
            env_id=self._env_id,
            participant_id=self._participant_id,
            scenario_id=self._scenario_id,
            details={
                "pid": process.pid,
                "euid": process.euid,
                "ppid": process.ppid,
                "cmd": process.cmd,
                "lstart": process.lstart,
                "process_id": process.process_id,
                "ppid_cmd": process.ppid_cmd,
                "ancestor_cmds": process.ancestor_cmds,
            },
        )
        self._on_event(event)
