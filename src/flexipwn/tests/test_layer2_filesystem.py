"""
Tests de FilesystemMonitor (Capa 2) — sin Docker real, todo mockeado.
"""
from unittest.mock import MagicMock

from docker.errors import NotFound

from flexipwn.layer2.filesystem import FilesystemMonitor


def _make_monitor(
    diff_returns=None,
    on_event=None,
    on_stopped=None,
    baseline: set[str] | None = None,
) -> tuple[FilesystemMonitor, MagicMock]:
    """Factory helper: crea un monitor con provider mockeado."""
    provider = MagicMock()
    if diff_returns is not None:
        provider.get_filesystem_diff.return_value = diff_returns
    # Simular _baselines del provider para inicializar _seen_paths
    provider._baselines = {"env-123": baseline or set()}

    on_event_cb = on_event or MagicMock()
    monitor = FilesystemMonitor(
        provider=provider,
        env_id="env-123",
        scenario_id="test-scenario",
        participant_id="test-player",
        on_event=on_event_cb,
        on_stopped=on_stopped,
    )
    return monitor, on_event_cb


class TestFilesystemMonitorPoll:

    def test_poll_emits_file_created_event(self):
        """Un diff con kind=1 debe emitir un MonitorEvent de tipo file_created."""
        monitor, on_event = _make_monitor(
            diff_returns=[{"kind": 1, "path": "/root/pwned.txt"}]
        )

        monitor._poll()

        on_event.assert_called_once()
        event = on_event.call_args[0][0]
        assert event.event_type == "file_created"
        assert event.details["path"] == "/root/pwned.txt"
        assert event.details["kind"] == 1
        assert event.monitor_type == "filesystem"
        assert event.env_id == "env-123"

    def test_poll_does_not_repeat_same_event(self):
        """Llamar _poll() dos veces con el mismo diff solo emite el evento una vez."""
        monitor, on_event = _make_monitor(
            diff_returns=[{"kind": 1, "path": "/root/pwned.txt"}]
        )

        monitor._poll()
        monitor._poll()

        on_event.assert_called_once()

    def test_poll_emits_file_modified_on_kind_change(self):
        """
        Si un path aparece como kind=1 (creado) y luego como kind=0 (modificado),
        se deben emitir dos eventos distintos.
        """
        provider = MagicMock()
        provider._baselines = {"env-123": set()}
        on_event = MagicMock()

        monitor = FilesystemMonitor(
            provider=provider,
            env_id="env-123",
            scenario_id="test-scenario",
            participant_id="test-player",
            on_event=on_event,
        )

        # Primera poll: kind=1 (creado)
        provider.get_filesystem_diff.return_value = [{"kind": 1, "path": "/tmp/exploit"}]
        monitor._poll()

        # Segunda poll: kind=0 (modificado)
        provider.get_filesystem_diff.return_value = [{"kind": 0, "path": "/tmp/exploit"}]
        monitor._poll()

        assert on_event.call_count == 2
        first_event = on_event.call_args_list[0][0][0]
        second_event = on_event.call_args_list[1][0][0]
        assert first_event.event_type == "file_created"
        assert second_event.event_type == "file_modified"

    def test_baseline_paths_not_reported(self):
        """
        Paths incluidos en el baseline del provider no deben generar eventos,
        aunque aparezcan en el diff.
        """
        monitor, on_event = _make_monitor(
            diff_returns=[{"kind": 0, "path": "/root/.bash_history"}],
            baseline={"/root/.bash_history"},
        )

        monitor._poll()

        on_event.assert_not_called()

    def test_baseline_paths_sentinel_in_seen(self):
        """Los paths de baseline se registran con kind=-1 en _seen_paths."""
        monitor, _ = _make_monitor(baseline={"/etc/apt"})
        assert monitor._seen_paths.get("/etc/apt") == -1


class TestFilesystemMonitorRun:

    def test_container_stopped_calls_on_stopped(self):
        """
        Si get_filesystem_diff lanza NotFound, el monitor debe llamar on_stopped
        con el env_id correcto y terminar el loop.
        """
        provider = MagicMock()
        provider._baselines = {"env-123": set()}
        provider.get_filesystem_diff.side_effect = NotFound("container gone")

        on_stopped = MagicMock()
        monitor = FilesystemMonitor(
            provider=provider,
            env_id="env-123",
            scenario_id="test-scenario",
            participant_id="test-player",
            on_event=MagicMock(),
            on_stopped=on_stopped,
        )

        monitor.run()

        on_stopped.assert_called_once_with("env-123")

    def test_stop_terminates_run_loop(self):
        """stop() debe hacer que el loop de run() termine tras el poll actual."""
        provider = MagicMock()
        provider._baselines = {"env-123": set()}

        call_count = 0

        def diff_side_effect(env_id):
            nonlocal call_count
            call_count += 1
            return []

        provider.get_filesystem_diff.side_effect = diff_side_effect

        monitor = FilesystemMonitor(
            provider=provider,
            env_id="env-123",
            scenario_id="test-scenario",
            participant_id="test-player",
            on_event=MagicMock(),
            poll_interval=0.0,
        )

        # stop() se llama en on_event, pero aquí lo llamamos directamente
        # después del primer poll via patch de sleep para que no bloquee
        original_run = monitor.run

        poll_calls = []

        def patched_poll():
            poll_calls.append(1)
            monitor.stop()

        monitor._poll = patched_poll
        monitor.run()

        # Solo debe haber llamado _poll una vez (stop() en el primero)
        assert len(poll_calls) == 1

    def test_run_handles_keyboard_interrupt_gracefully(self):
        """KeyboardInterrupt durante run() no debe propagar la excepción."""
        provider = MagicMock()
        provider._baselines = {"env-123": set()}
        provider.get_filesystem_diff.side_effect = KeyboardInterrupt

        monitor = FilesystemMonitor(
            provider=provider,
            env_id="env-123",
            scenario_id="test-scenario",
            participant_id="test-player",
            on_event=MagicMock(),
        )

        # No debe lanzar excepción
        monitor.run()
