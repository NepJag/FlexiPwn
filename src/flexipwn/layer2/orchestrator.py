from __future__ import annotations

import time
from collections.abc import Callable

from flexipwn.layer2.filesystem import FilesystemMonitor
from flexipwn.layer2.log import LogMonitor
from flexipwn.layer2.process import ProcessMonitor


class MonitorOrchestrator:
    """
    Orquesta FilesystemMonitor y ProcessMonitor en un loop bloqueante.

    En cada ciclo llama primero _poll() de filesystem y luego _poll()
    de procesos. El intervalo de polling y el timeout son responsabilidad
    exclusiva del orquestador — los monitores individuales no tienen
    concepto de tiempo ni de loop.

    Termina cuando:
    - Un monitor detecta que el contenedor se detuvo (vía on_stopped)
    - Se supera timeout_seconds (llama on_timeout y retorna)
    - Se llama stop()
    - KeyboardInterrupt

    Patrón de uso recomendado:

        orchestrator = MonitorOrchestrator(
            fs_monitor, proc_monitor,
            timeout_seconds=1800,
            on_timeout=handle_timeout,
        )

        def handle_stopped(env_id: str) -> None:
            orchestrator.stop()

        fs_monitor._on_stopped = handle_stopped
        proc_monitor._on_stopped = handle_stopped

        orchestrator.run()  # bloquea aquí
    """

    def __init__(
        self,
        filesystem_monitor: FilesystemMonitor,
        process_monitor: ProcessMonitor,
        log_monitor: LogMonitor | None = None,
        poll_interval: float = 2.0,
        timeout_seconds: int | None = None,
        on_timeout: Callable[[], None] | None = None,
    ) -> None:
        self._fs = filesystem_monitor
        self._proc = process_monitor
        self._log = log_monitor
        self._poll_interval = poll_interval
        self._timeout_seconds = timeout_seconds
        self._on_timeout = on_timeout
        self._running = False

    def run(self) -> None:
        """Loop bloqueante. Llama _poll() de cada monitor por ciclo."""
        self._running = True
        _start = time.monotonic()
        try:
            while self._running:
                if self._timeout_seconds is not None:
                    if time.monotonic() - _start >= self._timeout_seconds:
                        if self._on_timeout:
                            self._on_timeout()
                        return
                self._fs._poll()
                self._proc._poll()
                if self._log is not None:
                    self._log._poll()
                time.sleep(self._poll_interval)
        except KeyboardInterrupt:
            pass

    def stop(self) -> None:
        self._running = False
