"""
Tests de NetworkMonitor (Capa 2) — diseño packet-based.

El monitor procesa el output de tcpdump -A paquete por paquete:
- Cada paquete comienza con una línea de cabecera (timestamp + IPs + puertos + Flags).
- Las líneas siguientes hasta la próxima cabecera son el payload del paquete.
- El paquete actual se procesa cuando aparece la siguiente cabecera (o queda
  pendiente para el próximo poll si no llega).
"""
from pathlib import Path
from unittest.mock import MagicMock

from flexipwn.layer2.network import NetworkMonitor


def _make_monitor(capture_file: Path, on_event=None) -> tuple[NetworkMonitor, MagicMock]:
    on_event_cb = on_event or MagicMock()
    monitor = NetworkMonitor(
        env_id="env-test",
        participant_id="test-player",
        scenario_id="test-scenario",
        capture_file_path=capture_file,
        on_event=on_event_cb,
    )
    return monitor, on_event_cb


_HEADER_A = (
    b"12:34:56.789012 IP 172.20.0.2.54321 > 172.20.0.1.3306: "
    b"Flags [P.], seq 1:42, ack 1, win 512, length 41\n"
)
_HEADER_B = (
    b"12:34:57.123456 IP 172.20.0.1.3306 > 172.20.0.2.54321: "
    b"Flags [P.], seq 1:88, ack 42, win 512, length 87\n"
)
_HEADER_SYN_ACK = (
    b"12:34:55.000001 IP 192.168.1.10.4444 > 172.20.0.2.54321: "
    b"Flags [S.], seq 0, ack 1, win 512, length 0\n"
)
_HEADER_PLAIN_ACK = (
    b"12:34:55.000002 IP 172.20.0.2.54321 > 192.168.1.10.4444: "
    b"Flags [.], ack 1, win 512, length 0\n"
)


class TestPayloadEmission:

    def test_emits_network_payload_with_header_metadata(self, tmp_path):
        """Un paquete con cabecera + payload textual emite network_payload con IPs/puertos."""
        capture = tmp_path / "traffic.txt"
        capture.write_bytes(
            _HEADER_A
            + b"\x00\x00\x00\x00\x03SELECT * FROM users WHERE id=1\n"
            + _HEADER_B  # fuerza el flush del paquete anterior
        )

        monitor, on_event = _make_monitor(capture)
        monitor._poll()

        # Solo el primer paquete se flushó (el segundo queda pendiente)
        events = [c[0][0] for c in on_event.call_args_list]
        payload_events = [e for e in events if e.event_type == "network_payload"]
        assert len(payload_events) == 1
        ev = payload_events[0]
        assert ev.monitor_type == "network"
        assert "SELECT * FROM users WHERE id=1" in ev.details["data"]
        assert ev.details["src_ip"] == "172.20.0.2"
        assert ev.details["dst_ip"] == "172.20.0.1"
        assert ev.details["src_port"] == 54321
        assert ev.details["dst_port"] == 3306

    def test_concatenates_multiline_payload_from_same_packet(self, tmp_path):
        """Bytes \\x0a en el header parten el payload en líneas — todas se concatenan."""
        capture = tmp_path / "traffic.txt"
        capture.write_bytes(
            _HEADER_A
            + b"\x2e\x2e\x22\x32\x2e\x2e\n"
            + b"SELECT * FROM users WHERE username='admin' AND password='x'\n"
            + _HEADER_B
        )

        monitor, on_event = _make_monitor(capture)
        monitor._poll()

        payload_events = [
            c[0][0] for c in on_event.call_args_list
            if c[0][0].event_type == "network_payload"
        ]
        assert len(payload_events) == 1
        data = payload_events[0].details["data"]
        assert "SELECT" in data
        assert "users" in data
        assert "admin" in data

    def test_strips_non_printable_bytes_from_payload(self, tmp_path):
        """El campo data solo contiene bytes imprimibles 0x20-0x7e."""
        capture = tmp_path / "traffic.txt"
        capture.write_bytes(
            _HEADER_A
            + b"\x00\x01\x02SELECT\x00\x01 * FROM users\xff\xfe\n"
            + _HEADER_B
        )

        monitor, on_event = _make_monitor(capture)
        monitor._poll()

        ev = next(
            c[0][0] for c in on_event.call_args_list
            if c[0][0].event_type == "network_payload"
        )
        assert all(0x20 <= ord(c) <= 0x7e for c in ev.details["data"])
        assert "SELECT" in ev.details["data"]

    def test_no_payload_event_when_printable_text_too_short(self, tmp_path):
        """Payload con ≤4 chars imprimibles → no emite network_payload."""
        capture = tmp_path / "traffic.txt"
        capture.write_bytes(
            _HEADER_A
            + b"\x00\x00OK\x00\n"
            + _HEADER_B
        )

        monitor, on_event = _make_monitor(capture)
        monitor._poll()

        payload_events = [
            c[0][0] for c in on_event.call_args_list
            if c[0][0].event_type == "network_payload"
        ]
        assert payload_events == []

    def test_skips_missing_capture_file(self, tmp_path):
        """Archivo de captura inexistente → _poll() silencioso, sin eventos."""
        capture = tmp_path / "nonexistent.txt"
        monitor, on_event = _make_monitor(capture)

        monitor._poll()

        on_event.assert_not_called()


class TestConnectionDetection:

    def test_emits_network_connection_on_syn_ack_header(self, tmp_path):
        """Cabecera con Flags [S.] → evento network_connection con dst_port = puerto del servidor."""
        capture = tmp_path / "traffic.txt"
        capture.write_bytes(_HEADER_SYN_ACK + _HEADER_B)

        monitor, on_event = _make_monitor(capture)
        monitor._poll()

        conn_events = [
            c[0][0] for c in on_event.call_args_list
            if c[0][0].event_type == "network_connection"
        ]
        assert len(conn_events) == 1
        ev = conn_events[0]
        # En SYN-ACK el lado izquierdo es el servidor (destino lógico de la conexión).
        assert ev.details["dst_port"] == 4444
        assert ev.details["dst_ip"] == "192.168.1.10"
        assert ev.details["src_ip"] == "172.20.0.2"

    def test_does_not_emit_connection_for_plain_ack(self, tmp_path):
        """Flags [.] (ACK puro) no genera network_connection."""
        capture = tmp_path / "traffic.txt"
        capture.write_bytes(_HEADER_PLAIN_ACK + _HEADER_B)

        monitor, on_event = _make_monitor(capture)
        monitor._poll()

        for call in on_event.call_args_list:
            assert call[0][0].event_type != "network_connection"


class TestTcpdumpAnyInterfaceFormat:

    def test_parses_iface_direction_prefix_from_tcpdump_any(self, tmp_path):
        """tcpdump -i any intercala '<iface> <In|Out>' entre timestamp e IP.
        El monitor debe parsearlo y emitir network_payload con IPs/puertos correctos."""
        capture = tmp_path / "traffic.txt"
        capture.write_bytes(
            b"03:03:27.634632 lo    In  IP 127.0.0.1.50308 > 127.0.0.1.5000: "
            b"Flags [P.], seq 1:125, ack 1, win 512, length 124\n"
            b"GET /health HTTP/1.1\nHost: localhost:5000\n"
            b"03:03:27.635429 lo    In  IP 127.0.0.1.5000 > 127.0.0.1.50308: "
            b"Flags [.], ack 1, win 512, length 0\n"
        )

        monitor, on_event = _make_monitor(capture)
        monitor._poll()

        payload_events = [
            c[0][0] for c in on_event.call_args_list
            if c[0][0].event_type == "network_payload"
        ]
        assert len(payload_events) >= 1
        ev = payload_events[0]
        assert "GET /health" in ev.details["data"]
        assert ev.details["src_ip"] == "127.0.0.1"
        assert ev.details["dst_ip"] == "127.0.0.1"
        assert ev.details["src_port"] == 50308
        assert ev.details["dst_port"] == 5000

    def test_parses_iface_direction_prefix_for_ipv6(self, tmp_path):
        """Mismo prefijo de interfaz para IPv6 (IP6) — debe aceptarlo igual."""
        capture = tmp_path / "traffic.txt"
        capture.write_bytes(
            b"03:03:27.634495 lo    In  IP6 ::1.37662 > ::1.5000: "
            b"Flags [S], seq 1, win 512, length 0\n"
            b"some payload data here for testing\n"
            b"03:03:27.634502 lo    In  IP6 ::1.5000 > ::1.37662: "
            b"Flags [R.], seq 0, ack 1, win 0, length 0\n"
        )

        monitor, on_event = _make_monitor(capture)
        monitor._poll()

        payload_events = [
            c[0][0] for c in on_event.call_args_list
            if c[0][0].event_type == "network_payload"
        ]
        assert len(payload_events) >= 1
        assert "payload data" in payload_events[0].details["data"]


class TestPacketBuffering:

    def test_single_packet_is_flushed_in_same_poll(self, tmp_path):
        """Un único paquete (header + payload, sin header siguiente) se emite
        en el mismo _poll() — el flush al final del loop evita que quede atrapado."""
        capture = tmp_path / "traffic.txt"
        capture.write_bytes(
            _HEADER_A + b"\x00\x00\x00\x00SELECT * FROM users\n"
        )

        monitor, on_event = _make_monitor(capture)
        monitor._poll()

        payload_events = [
            c[0][0] for c in on_event.call_args_list
            if c[0][0].event_type == "network_payload"
        ]
        assert len(payload_events) == 1
        assert "SELECT * FROM users" in payload_events[0].details["data"]

    def test_pending_packet_does_not_re_emit_on_repeated_poll(self, tmp_path):
        """Tras el flush al final del primer poll, un segundo poll sin datos
        nuevos no re-emite el mismo paquete."""
        capture = tmp_path / "traffic.txt"
        capture.write_bytes(
            _HEADER_A + b"\x00\x00\x00\x00SELECT * FROM users\n"
        )

        monitor, on_event = _make_monitor(capture)
        monitor._poll()
        first = on_event.call_count
        monitor._poll()
        assert on_event.call_count == first


class TestDeduplication:

    def test_no_duplicate_events_on_repeated_poll(self, tmp_path):
        """Dos polls sin cambios en el archivo → no se reprocesan paquetes."""
        capture = tmp_path / "traffic.txt"
        capture.write_bytes(
            _HEADER_A + b"\x00\x00\x00\x00SELECT 1\n" + _HEADER_B
        )

        monitor, on_event = _make_monitor(capture)
        monitor._poll()
        first_count = on_event.call_count
        monitor._poll()
        assert on_event.call_count == first_count

    def test_offset_advances_between_polls(self, tmp_path):
        """El offset avanza con cada poll para no reprocesar bytes."""
        capture = tmp_path / "traffic.txt"
        capture.write_bytes(_HEADER_A + b"payload\n" + _HEADER_B)

        monitor, _ = _make_monitor(capture)
        assert monitor._offset == 0
        monitor._poll()
        assert monitor._offset == len(capture.read_bytes())
