"""
Tests de LogMonitor (Capa 2) — sin Docker, todo en archivos temporales.
"""
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from flexipwn.layer2.log import LogMonitor


def _make_monitor(log_paths: list[str], on_event=None) -> tuple[LogMonitor, MagicMock]:
    on_event_cb = on_event or MagicMock()
    monitor = LogMonitor(
        log_paths=log_paths,
        env_id="env-test",
        scenario_id="test-scenario",
        participant_id="test-player",
        on_event=on_event_cb,
    )
    return monitor, on_event_cb


class TestLogMonitorPoll:

    def test_log_monitor_parses_json_line(self, tmp_path):
        """Línea JSON válida → on_event con details['parsed']."""
        log_file = tmp_path / "app.log"
        monitor, on_event = _make_monitor([str(log_file)])

        # Primera poll: inicializa posición al final (archivo vacío → pos=0)
        log_file.write_text("")
        monitor._poll()

        # Escribir línea JSON
        payload = {"event_type": "authentication_success", "username": "admin"}
        log_file.write_text(json.dumps(payload) + "\n")

        monitor._poll()

        assert on_event.call_count == 1
        event = on_event.call_args[0][0]
        assert event.event_type == "log_entry"
        assert event.monitor_type == "log"
        assert event.details["parsed"]["event_type"] == "authentication_success"
        assert "raw_line" not in event.details

    def test_log_monitor_handles_plain_text(self, tmp_path):
        """Línea no-JSON → on_event con details['raw_line']."""
        log_file = tmp_path / "mysql.log"
        monitor, on_event = _make_monitor([str(log_file)])

        log_file.write_text("")
        monitor._poll()  # inicializa

        log_file.write_text("2024-01-01T00:00:00 Query SELECT * FROM users\n")
        monitor._poll()

        assert on_event.call_count == 1
        event = on_event.call_args[0][0]
        assert "raw_line" in event.details
        assert "SELECT" in event.details["raw_line"]
        assert "parsed" not in event.details

    def test_log_monitor_detects_truncation(self, tmp_path):
        """Si el archivo encoge, hace seek(0) y relee desde el inicio."""
        log_file = tmp_path / "general.log"

        # Escribir contenido inicial grande
        original_content = "line one\n" * 10
        log_file.write_text(original_content)

        monitor, on_event = _make_monitor([str(log_file)])
        monitor._poll()  # inicializa al final

        # Truncar el archivo con contenido nuevo más corto
        log_file.write_text("new line after truncation\n")
        monitor._poll()

        # Debe haber leído "new line after truncation" desde el inicio
        assert on_event.call_count == 1
        event = on_event.call_args[0][0]
        assert event.details["raw_line"] == "new line after truncation"

    def test_log_monitor_skips_missing_file(self, tmp_path):
        """Archivo inexistente → _poll() no lanza excepción y no emite eventos."""
        missing = str(tmp_path / "does_not_exist.log")
        monitor, on_event = _make_monitor([missing])

        # No debe lanzar excepción
        monitor._poll()
        monitor._poll()

        on_event.assert_not_called()

    def test_log_monitor_no_historical_on_init(self, tmp_path):
        """Líneas previas a la creación del monitor no se reportan."""
        log_file = tmp_path / "app.log"
        # Escribir 5 líneas antes de crear el monitor
        log_file.write_text("\n".join([f"old line {i}" for i in range(5)]) + "\n")

        monitor, on_event = _make_monitor([str(log_file)])

        # Primera poll: debe inicializar y hacer seek al final sin emitir
        monitor._poll()
        assert on_event.call_count == 0

        # Segunda poll sin nuevas líneas: tampoco emite
        monitor._poll()
        assert on_event.call_count == 0
