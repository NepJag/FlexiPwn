"""
Tests de ProcessMonitor (Capa 2) y ProcessRunningEvaluator (Capa 3) — sin Docker real.
"""
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from flexipwn.layer1.provider import ProcessInfo, make_process_id
from flexipwn.layer2.events import MonitorEvent
from flexipwn.layer2.process import ProcessMonitor
from flexipwn.layer3.schema import TargetConfig
from flexipwn.layer3.targets.process import ProcessRunningEvaluator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_process(
    pid: str = "100",
    euid: int = 0,
    ppid: str = "1",
    cmd: str = "/bin/bash",
    lstart: str = "",
    ppid_cmd: str = "",
    ancestor_cmds: list | None = None,
) -> ProcessInfo:
    process_id = make_process_id(pid, lstart) if lstart else make_process_id(pid, cmd)
    return ProcessInfo(
        pid=pid,
        euid=euid,
        ppid=ppid,
        cmd=cmd,
        lstart=lstart,
        process_id=process_id,
        ppid_cmd=ppid_cmd,
        ancestor_cmds=ancestor_cmds or [],
    )


def _make_monitor(
    processes_sequence: list[list[ProcessInfo]],
    on_event: MagicMock | None = None,
    on_stopped: MagicMock | None = None,
) -> tuple[ProcessMonitor, MagicMock]:
    provider = MagicMock()
    provider.get_processes.side_effect = processes_sequence

    on_event_cb = on_event or MagicMock()
    monitor = ProcessMonitor(
        provider=provider,
        env_id="env-123",
        scenario_id="test-scenario",
        participant_id="test-player",
        on_event=on_event_cb,
        on_stopped=on_stopped,
    )
    return monitor, on_event_cb


def _make_process_spawned_event(
    euid: int = 0,
    cmd: str = "/bin/bash -i",
    ppid: str = "1",
    ppid_cmd: str = "",
    ancestor_cmds: list | None = None,
) -> MonitorEvent:
    return MonitorEvent(
        timestamp=datetime.now(timezone.utc),
        monitor_type="process",
        event_type="process_spawned",
        env_id="env-123",
        participant_id="test-player",
        scenario_id="test-scenario",
        details={
            "pid": "999",
            "euid": euid,
            "ppid": ppid,
            "cmd": cmd,
            "lstart": "",
            "process_id": make_process_id("999", cmd),
            "ppid_cmd": ppid_cmd,
            "ancestor_cmds": ancestor_cmds or [],
        },
    )


# ---------------------------------------------------------------------------
# ProcessMonitor
# ---------------------------------------------------------------------------


class TestProcessMonitorBaseline:

    def test_baseline_taken_on_first_poll(self):
        """Primera llamada a _poll() con 3 procesos: baseline capturado, on_event no llamado."""
        procs = [_make_process(pid=str(i), ppid="1", cmd=f"/bin/proc{i}") for i in range(3)]
        monitor, on_event = _make_monitor(processes_sequence=[procs])

        monitor._poll()

        assert monitor._baseline is not None
        assert len(monitor._baseline) == 3
        on_event.assert_not_called()

    def test_new_process_emits_spawned_event(self):
        """Segunda poll con un proceso adicional: on_event llamado exactamente una vez."""
        base_procs = [_make_process(pid="1", ppid="0", cmd="bash")]
        new_proc = _make_process(pid="200", ppid="1", cmd="bash")

        monitor, on_event = _make_monitor(
            processes_sequence=[base_procs, base_procs + [new_proc]]
        )

        monitor._poll()  # baseline
        monitor._poll()  # detecta nuevo proceso

        on_event.assert_called_once()
        event = on_event.call_args[0][0]
        assert event.event_type == "process_spawned"
        assert event.monitor_type == "process"
        assert event.details["pid"] == "200"

    def test_existing_process_not_reported_again(self):
        """Tres polls con los mismos procesos: on_event nunca llamado."""
        procs = [_make_process(pid="1", ppid="0", cmd="bash")]
        monitor, on_event = _make_monitor(processes_sequence=[procs, procs, procs])

        monitor._poll()  # baseline
        monitor._poll()  # sin cambios
        monitor._poll()  # sin cambios

        on_event.assert_not_called()

    def test_process_id_collision_prevention(self):
        """
        Reutilización de PID: proceso pid=123 (bash) desaparece y aparece otro
        con mismo pid=123 pero distinto cmd → process_ids distintos (hash pid:cmd)
        → segundo proceso SÍ emite evento.
        """
        proc_a = _make_process(pid="123", ppid="1", cmd="/bin/bash")
        proc_b = _make_process(pid="123", ppid="1", cmd="/bin/sh")  # mismo pid, distinto cmd

        # Asegurar que los process_ids son distintos
        assert proc_a.process_id != proc_b.process_id

        monitor, on_event = _make_monitor(
            processes_sequence=[[proc_a], [proc_b]]  # pid=123 reaparece con nuevo cmd
        )

        monitor._poll()  # baseline: proc_a en baseline
        monitor._poll()  # proc_b tiene distinto process_id → se emite

        on_event.assert_called_once()
        event = on_event.call_args[0][0]
        assert event.event_type == "process_spawned"
        assert event.details["pid"] == "123"
        assert event.details["process_id"] == proc_b.process_id

    def test_event_details_complete(self):
        """El evento emitido debe incluir todos los campos de details."""
        base_procs = [_make_process(pid="1", ppid="0", cmd="bash")]
        new_proc = _make_process(
            pid="500",
            euid=1000,
            ppid="1",
            cmd="/usr/bin/python3 script.py",
            ppid_cmd="bash",
            ancestor_cmds=["bash", "init"],
        )
        monitor, on_event = _make_monitor(
            processes_sequence=[base_procs, base_procs + [new_proc]]
        )

        monitor._poll()
        monitor._poll()

        event = on_event.call_args[0][0]
        details = event.details
        assert details["pid"] == "500"
        assert details["euid"] == 1000
        assert details["ppid"] == "1"
        assert details["cmd"] == "/usr/bin/python3 script.py"
        assert len(details["process_id"]) == 12
        assert details["ppid_cmd"] == "bash"
        assert details["ancestor_cmds"] == ["bash", "init"]


class TestProcessMonitorStopped:

    def test_container_not_found_calls_on_stopped(self):
        """Si get_processes lanza NotFound, debe llamar on_stopped con env_id."""
        from docker.errors import NotFound

        provider = MagicMock()
        provider.get_processes.side_effect = NotFound("gone")
        on_stopped = MagicMock()

        monitor = ProcessMonitor(
            provider=provider,
            env_id="env-123",
            scenario_id="s",
            participant_id="p",
            on_event=MagicMock(),
            on_stopped=on_stopped,
        )
        monitor._poll()

        on_stopped.assert_called_once_with("env-123")

    def test_container_not_running_api_error_calls_on_stopped(self):
        """APIError con 'is not running' debe llamar on_stopped."""
        from docker.errors import APIError

        provider = MagicMock()
        provider.get_processes.side_effect = APIError("Container is not running")
        on_stopped = MagicMock()

        monitor = ProcessMonitor(
            provider=provider,
            env_id="env-123",
            scenario_id="s",
            participant_id="p",
            on_event=MagicMock(),
            on_stopped=on_stopped,
        )
        monitor._poll()

        on_stopped.assert_called_once_with("env-123")


# ---------------------------------------------------------------------------
# ProcessRunningEvaluator
# ---------------------------------------------------------------------------


class TestProcessRunningEvaluator:

    def _make_evaluator(
        self,
        euid: int = 0,
        cmd_contains: str = "/bin/bash",
        ppid_cmd_contains: str | None = None,
        ancestor_contains: str | None = None,
    ) -> ProcessRunningEvaluator:
        config = TargetConfig(
            type="process_running",
            description="test",
            euid=euid,
            cmd_contains=cmd_contains,
            ppid_cmd_contains=ppid_cmd_contains,
            ancestor_contains=ancestor_contains,
        )
        return ProcessRunningEvaluator(config)

    def test_matches_root_bash(self):
        """Evento process_spawned con euid=0 y cmd conteniendo '/bin/bash' → match."""
        evaluator = self._make_evaluator(euid=0, cmd_contains="/bin/bash")
        event = _make_process_spawned_event(euid=0, cmd="/bin/bash -i")

        assert evaluator.matches(event) is True

    def test_no_match_wrong_euid(self):
        """Mismo evento pero euid=1000 → no match."""
        evaluator = self._make_evaluator(euid=0, cmd_contains="/bin/bash")
        event = _make_process_spawned_event(euid=1000, cmd="/bin/bash -i")

        assert evaluator.matches(event) is False

    def test_no_match_wrong_cmd(self):
        """euid correcto pero cmd no contiene el substring → no match."""
        evaluator = self._make_evaluator(euid=0, cmd_contains="/bin/bash")
        event = _make_process_spawned_event(euid=0, cmd="/usr/bin/python3")

        assert evaluator.matches(event) is False

    def test_no_match_wrong_event_type(self):
        """Evento de tipo file_created → no match (solo process_spawned)."""
        evaluator = self._make_evaluator(euid=0, cmd_contains="/bin/bash")
        event = MonitorEvent(
            timestamp=datetime.now(timezone.utc),
            monitor_type="filesystem",
            event_type="file_created",
            env_id="env-123",
            participant_id="p",
            scenario_id="s",
            details={"path": "/root/x.txt", "kind": 1},
        )

        assert evaluator.matches(event) is False

    def test_cmd_contains_substring_match(self):
        """cmd_contains puede ser un substring, no necesariamente la ruta completa."""
        evaluator = self._make_evaluator(euid=0, cmd_contains="bash")
        event = _make_process_spawned_event(euid=0, cmd="/usr/bin/bash --noprofile")

        assert evaluator.matches(event) is True

    def test_process_running_ppid_filter_blocks_sudo_bash(self):
        """
        sudo bash directo: padre es 'bash' o 'sudo', no vim.
        Con ppid_cmd_contains='vim' → no match.
        """
        evaluator = self._make_evaluator(
            euid=0, cmd_contains="bash", ppid_cmd_contains="vim"
        )
        event = _make_process_spawned_event(
            euid=0, cmd="bash", ppid_cmd="bash"
        )

        assert evaluator.matches(event) is False

    def test_process_running_ppid_filter_allows_vim_bash(self):
        """
        sudo vim → :!bash: padre es vim.
        Con ppid_cmd_contains='vim' → match.
        """
        evaluator = self._make_evaluator(
            euid=0, cmd_contains="bash", ppid_cmd_contains="vim"
        )
        event = _make_process_spawned_event(
            euid=0, cmd="bash", ppid_cmd="vim /etc/hosts"
        )

        assert evaluator.matches(event) is True

    def test_process_running_ancestor_filter(self):
        """
        ancestor_cmds contiene 'sudo' en la cadena → match con ancestor_contains='sudo'.
        """
        evaluator = self._make_evaluator(
            euid=0, cmd_contains="bash", ancestor_contains="sudo"
        )
        event = _make_process_spawned_event(
            euid=0,
            cmd="bash",
            ancestor_cmds=["vim /etc/hosts", "sudo vim", "bash"],
        )

        assert evaluator.matches(event) is True

    def test_process_running_no_ancestor_match(self):
        """
        ancestor_cmds no contiene 'vim' → no match con ancestor_contains='vim'.
        """
        evaluator = self._make_evaluator(
            euid=0, cmd_contains="bash", ancestor_contains="vim"
        )
        event = _make_process_spawned_event(
            euid=0,
            cmd="bash",
            ancestor_cmds=["bash", "init"],
        )

        assert evaluator.matches(event) is False

    def test_ppid_and_ancestor_both_required(self):
        """
        Ambos filtros opcionales activos: ppid OK pero ancestor falla → no match.
        """
        evaluator = self._make_evaluator(
            euid=0,
            cmd_contains="bash",
            ppid_cmd_contains="vim",
            ancestor_contains="sudo",
        )
        # ppid_cmd contiene 'vim' pero ancestor_cmds no contiene 'sudo'
        event = _make_process_spawned_event(
            euid=0,
            cmd="bash",
            ppid_cmd="vim",
            ancestor_cmds=["bash"],
        )

        assert evaluator.matches(event) is False


# ---------------------------------------------------------------------------
# MonitorOrchestrator
# ---------------------------------------------------------------------------


class TestMonitorOrchestrator:

    def test_orchestrator_calls_both_monitors_per_cycle(self):
        """
        Mockear _poll() de ambos monitores. Correr orchestrator y detener
        después de 1 ciclo. Verificar que ambos _poll() fueron llamados exactamente una vez.
        """
        from flexipwn.layer2.orchestrator import MonitorOrchestrator

        fs_monitor = MagicMock()
        proc_monitor = MagicMock()

        orchestrator = MonitorOrchestrator(fs_monitor, proc_monitor, poll_interval=0.0)

        call_count = 0

        def fs_poll():
            nonlocal call_count
            call_count += 1
            orchestrator.stop()  # detener después del primer ciclo

        fs_monitor._poll.side_effect = fs_poll

        orchestrator.run()

        fs_monitor._poll.assert_called_once()
        proc_monitor._poll.assert_called_once()

    def test_orchestrator_stops_on_keyboard_interrupt(self):
        """KeyboardInterrupt en el loop no debe propagar la excepción."""
        from flexipwn.layer2.orchestrator import MonitorOrchestrator

        fs_monitor = MagicMock()
        proc_monitor = MagicMock()

        orchestrator = MonitorOrchestrator(fs_monitor, proc_monitor, poll_interval=0.0)
        fs_monitor._poll.side_effect = KeyboardInterrupt

        # No debe lanzar excepción
        orchestrator.run()

    def test_orchestrator_calls_on_timeout(self):
        """Cuando se supera timeout_seconds, el orquestador llama on_timeout y termina."""
        from flexipwn.layer2.orchestrator import MonitorOrchestrator

        fs_monitor = MagicMock()
        proc_monitor = MagicMock()
        on_timeout = MagicMock()

        # Timeout de 0s → expira inmediatamente en el primer ciclo
        orchestrator = MonitorOrchestrator(
            fs_monitor, proc_monitor,
            poll_interval=0.0,
            timeout_seconds=0,
            on_timeout=on_timeout,
        )
        orchestrator.run()

        on_timeout.assert_called_once()
        # Los monitores no deben haber sido llamados (timeout antes del primer poll)
        fs_monitor._poll.assert_not_called()
        proc_monitor._poll.assert_not_called()
