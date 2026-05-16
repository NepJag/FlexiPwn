from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from flexipwn.layer2.events import MonitorEvent


class NetworkMonitor:
    """
    Monitorea tráfico de red leyendo incrementalmente el output de tcpdump -A.

    Procesa el output paquete por paquete: cada paquete comienza con una línea
    de cabecera tcpdump (timestamp + IPs + puertos + Flags), seguida de líneas
    de payload hasta la próxima cabecera. El payload se concatena y se extrae
    todo el texto imprimible para emitirlo como network_payload.

    Si la cabecera contiene "Flags [S.]" se emite también network_connection.
    """

    # Cabecera tcpdump: HH:MM:SS.micros [<iface> <In|Out>] IP src.port > dst.port: Flags [...]
    # Con `-i any`, tcpdump intercala el nombre de la interfaz y la dirección
    # ("lo    In  IP ..."); con `-i <iface>` específico, va directo a "IP ...".
    _HEADER_RE = re.compile(
        rb'^(\d{2}:\d{2}:\d{2}\.\d+)\s+(?:\S+\s+\S+\s+)?IP6?\s+'
        rb'([\w\.\-:]+?)\.(\d+)\s+>\s+([\w\.\-:]+?)\.(\d+):\s+Flags'
    )

    def __init__(
        self,
        env_id: str,
        participant_id: str,
        scenario_id: str,
        capture_file_path: Path,
        on_event: Callable[[MonitorEvent], None],
        poll_interval: float = 1.0,
    ) -> None:
        self._env_id = env_id
        self._participant_id = participant_id
        self._scenario_id = scenario_id
        self._capture_file_path = capture_file_path
        self._on_event = on_event
        self._poll_interval = poll_interval
        self._offset: int = 0
        self._current_header: dict | None = None
        self._payload_buffer: list[bytes] = []

    def _poll(self) -> None:
        if not self._capture_file_path.exists():
            return
        try:
            with open(self._capture_file_path, "rb") as f:
                f.seek(self._offset)
                new_data = f.read()
            self._offset += len(new_data)
        except (OSError, IOError):
            return

        for line in new_data.splitlines(keepends=False):
            header = self._parse_header(line)
            if header is not None:
                # Flush packet en curso (si hay) antes de iniciar uno nuevo.
                if self._current_header is not None:
                    self._process_packet()
                self._current_header = header
                self._payload_buffer = []
            else:
                if self._current_header is not None:
                    self._payload_buffer.append(line)
        # Flush del paquete en curso al final del bloque leído: sin esto, el
        # último paquete de una transacción corta queda atrapado hasta que
        # llegue otro header (que en escenarios cortos puede no ocurrir).
        if self._current_header is not None and self._payload_buffer:
            self._process_packet()
            self._current_header = None
            self._payload_buffer = []

    def _parse_header(self, line: bytes) -> dict | None:
        m = self._HEADER_RE.match(line)
        if m is None:
            return None
        try:
            return {
                "src_ip": m.group(2).decode(),
                "src_port": int(m.group(3)),
                "dst_ip": m.group(4).decode(),
                "dst_port": int(m.group(5)),
                "is_syn_ack": b'Flags [S.]' in line,
            }
        except (ValueError, UnicodeDecodeError):
            return None

    def _process_packet(self) -> None:
        header = self._current_header
        if header is None:
            return

        # Concatenar todas las líneas del payload y extraer texto imprimible.
        joined = b"\n".join(self._payload_buffer)
        printable = re.sub(rb'[^\x20-\x7e]', b'', joined).decode('ascii', errors='ignore')

        if len(printable) > 4:
            self._emit_event("network_payload", {
                "data": printable,
                "src_ip": header["src_ip"],
                "dst_ip": header["dst_ip"],
                "src_port": header["src_port"],
                "dst_port": header["dst_port"],
            })

        if header["is_syn_ack"]:
            # SYN-ACK va de SERVIDOR → CLIENTE: el lado izquierdo (src de la
            # cabecera) es el servidor, destino lógico de la conexión.
            self._emit_event("network_connection", {
                "src_ip": header["dst_ip"],
                "dst_ip": header["src_ip"],
                "dst_port": header["src_port"],
            })

    def _emit_event(self, event_type: str, details: dict) -> None:
        event = MonitorEvent(
            timestamp=datetime.now(UTC),
            monitor_type="network",
            event_type=event_type,
            env_id=self._env_id,
            participant_id=self._participant_id,
            scenario_id=self._scenario_id,
            details=details,
        )
        self._on_event(event)
