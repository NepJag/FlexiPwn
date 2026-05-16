from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from flexipwn.layer2.events import MonitorEvent

OnEventCallback = Callable[[MonitorEvent], None]
OnStoppedCallback = Callable[[str], None]


class LogMonitor:
    """
    Monitorea archivos de log escritos por el contenedor en el host
    a través de volúmenes Docker.

    Principio de pasividad: solo lee archivos del host. No ejecuta
    nada dentro del contenedor.

    Modo de parseo por línea (auto-detectado):
    - Si la línea es JSON válido: expone campos parseados en details["parsed"]
    - Si no es JSON: expone la línea completa en details["raw_line"]

    Robusto ante truncamiento: si el archivo decrece en tamaño (app
    reinició y truncó el log), hace seek al inicio y relee desde el
    principio.
    """

    def __init__(
        self,
        log_paths: list[str],
        env_id: str,
        scenario_id: str,
        participant_id: str,
        on_event: OnEventCallback,
        on_stopped: OnStoppedCallback | None = None,
    ) -> None:
        # log_paths: rutas en el HOST (ya resueltas por Capa 4 desde el YAML)
        self._log_paths = log_paths
        self._env_id = env_id
        self._scenario_id = scenario_id
        self._participant_id = participant_id
        self._on_event = on_event
        self._on_stopped = on_stopped
        # Estado por archivo: {path: {"position": int, "size": int}}
        self._file_states: dict[str, dict] = {}

    def _poll(self) -> None:
        """
        Una iteración del loop. Para cada path en log_paths:
        1. Verificar si el archivo existe (puede no existir aún si la app
           no ha arrancado). Si no existe, saltar silenciosamente.
        2. Abrir el archivo y comparar tamaño actual con el último conocido.
           Si el tamaño disminuyó, el archivo fue truncado: hacer seek(0).
           Si es la primera vez, hacer seek al final (no reportar histórico).
        3. Leer líneas nuevas hasta EOF.
        4. Para cada línea no vacía, intentar parsear como JSON.
           - Si es JSON válido: emitir event_type="log_entry" con
             details={"source_file": path, "parsed": dict}
           - Si no es JSON: emitir event_type="log_entry" con
             details={"source_file": path, "raw_line": str}
        """
        for log_path in self._log_paths:
            path = Path(log_path)
            if not path.exists():
                continue
            try:
                current_size = path.stat().st_size
                state = self._file_states.get(log_path)

                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    if state is None:
                        # Primera vez: seek al final, no reportar histórico
                        f.seek(0, 2)
                        self._file_states[log_path] = {
                            "position": f.tell(),
                            "size": current_size,
                        }
                        continue

                    if current_size < state["size"]:
                        # Truncamiento detectado: releer desde el inicio
                        f.seek(0)
                    else:
                        f.seek(state["position"])

                    for line in f:
                        line = line.rstrip("\n")
                        if not line.strip():
                            continue
                        self._emit_event(line, log_path)

                    self._file_states[log_path] = {
                        "position": f.tell(),
                        "size": current_size,
                    }
            except (OSError, IOError):
                # Archivo inaccesible temporalmente, reintentar en próximo poll
                pass

    def _emit_event(self, line: str, source_file: str) -> None:
        """
        Construye y emite un MonitorEvent de tipo log_entry.
        Auto-detecta si la línea es JSON o texto plano.
        """
        try:
            parsed = json.loads(line)
            details: dict = {"source_file": source_file, "parsed": parsed}
        except (json.JSONDecodeError, ValueError):
            details = {"source_file": source_file, "raw_line": line}

        event = MonitorEvent(
            timestamp=datetime.now(timezone.utc),
            monitor_type="log",
            event_type="log_entry",
            env_id=self._env_id,
            participant_id=self._participant_id,
            scenario_id=self._scenario_id,
            details=details,
        )
        self._on_event(event)
