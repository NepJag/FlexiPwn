"""Tests unitarios para Layer 1 — no requieren Docker."""

from unittest.mock import MagicMock, patch

import pytest

from flexipwn.config import FlexiPwnConfig
from flexipwn.layer1.docker_rootless import (
    DockerRootlessProvider,
    _generate_env_id,
    _resolve_ancestors,
)
from flexipwn.layer1.provider import (
    ContainerStartError,
    EnvironmentNotFoundError,
    ImageNotFoundError,
    ProcessInfo,
    ProviderError,
    SocketNotFoundError,
    make_process_id,
)


class TestGenerateEnvId:
    def test_format(self):
        env_id = _generate_env_id()
        assert env_id.startswith("run-")
        assert len(env_id) == 12  # "run-" (4) + 8 hex chars

    def test_uniqueness(self):
        ids = {_generate_env_id() for _ in range(100)}
        assert len(ids) == 100


class TestSocketDetection:
    @patch.dict("os.environ", {}, clear=True)
    @patch("flexipwn.layer1.docker_rootless._detect_socket")
    def test_socket_not_found_raises(self, mock_detect):
        mock_detect.side_effect = SocketNotFoundError(
            "No se encontró un socket Docker rootless."
        )
        with pytest.raises(SocketNotFoundError, match="No se encontró"):
            DockerRootlessProvider(config=FlexiPwnConfig())


class TestRollbackOnFailure:
    @patch("flexipwn.layer1.docker_rootless._detect_socket", return_value="unix:///fake.sock")
    def test_destroy_calls_rollback_on_partial_failure(self, _mock_detect, tmp_path):
        """Si el contenedor falla al crearse, se limpian red y directorios."""
        mock_client = MagicMock()
        config = FlexiPwnConfig(volumes_base_path=str(tmp_path / "vols"))

        # La red se crea correctamente
        mock_network = MagicMock()
        mock_client.networks.create.return_value = mock_network
        mock_client.networks.get.return_value = mock_network

        # El contenedor falla al crearse
        from docker.errors import APIError, NotFound

        mock_client.containers.run.side_effect = APIError("boom")
        # Los containers.get en rollback no encuentran nada (aún no se crearon)
        mock_client.containers.get.side_effect = NotFound("not found")

        provider = DockerRootlessProvider(config=config, client=mock_client)

        with pytest.raises(ContainerStartError):
            provider.create(
                scenario_id="test-scenario",
                participant_id="student-1",
                image="ubuntu:22.04",
            )

        # Verificar que se hizo rollback de la red
        mock_network.remove.assert_called_once()

        # Verificar que se limpiaron los directorios
        vols_dir = tmp_path / "vols"
        assert not any(vols_dir.iterdir()) if vols_dir.exists() else True


class TestCreateVolumes:
    @patch("flexipwn.layer1.docker_rootless.time.sleep")
    @patch("flexipwn.layer1.docker_rootless._detect_socket", return_value="unix:///fake.sock")
    def test_create_does_not_mount_system_dirs(self, _mock_detect, _mock_sleep, tmp_path):
        """create() no debe montar /etc, /root ni /home como bind mounts."""
        mock_client = MagicMock()
        config = FlexiPwnConfig(volumes_base_path=str(tmp_path / "vols"))

        # Contenedor sin healthcheck para evitar loop de polling
        mock_container = MagicMock()
        mock_container.attrs = {"State": {}}
        mock_container.diff.return_value = []
        mock_client.containers.get.return_value = mock_container

        provider = DockerRootlessProvider(config=config, client=mock_client)
        provider.create(
            scenario_id="test",
            participant_id="student-1",
            image="ubuntu:22.04",
        )

        call_kwargs = mock_client.containers.run.call_args
        volumes = call_kwargs.kwargs.get("volumes", call_kwargs.args[1] if len(call_kwargs.args) > 1 else {})

        system_paths = {"/etc", "/root", "/home"}
        mounted_binds = set()
        if isinstance(volumes, dict):
            for v in volumes.values():
                if isinstance(v, dict) and "bind" in v:
                    mounted_binds.add(v["bind"])

        assert mounted_binds.isdisjoint(system_paths), (
            f"Se encontraron bind mounts de sistema: {mounted_binds & system_paths}"
        )


class TestErrorHandling:
    @patch("flexipwn.layer1.docker_rootless._detect_socket", return_value="unix:///fake.sock")
    def test_image_not_found_raises(self, _mock_detect, tmp_path):
        """create() con imagen inexistente lanza ImageNotFoundError."""
        from docker.errors import ImageNotFound

        mock_client = MagicMock()
        mock_client.networks.create.return_value = MagicMock()
        mock_client.containers.run.side_effect = ImageNotFound("no such image")
        mock_client.containers.get.side_effect = __import__("docker").errors.NotFound("not found")

        config = FlexiPwnConfig(volumes_base_path=str(tmp_path / "vols"))
        provider = DockerRootlessProvider(config=config, client=mock_client)

        with pytest.raises(ImageNotFoundError, match="no encontrada"):
            provider.create(
                scenario_id="test",
                participant_id="student-1",
                image="imagen-que-no-existe:latest",
            )

    @patch("flexipwn.layer1.docker_rootless._detect_socket", return_value="unix:///fake.sock")
    def test_environment_not_found_raises_on_exec(self, _mock_detect):
        """exec_run() sobre un env_id inexistente lanza EnvironmentNotFoundError."""
        from docker.errors import NotFound

        mock_client = MagicMock()
        mock_client.containers.get.side_effect = NotFound("not found")

        provider = DockerRootlessProvider(config=FlexiPwnConfig(), client=mock_client)

        with pytest.raises(EnvironmentNotFoundError):
            provider.exec_run("run-no-existe", "whoami")

    @patch("flexipwn.layer1.docker_rootless._detect_socket", return_value="unix:///fake.sock")
    def test_environment_not_found_raises_on_get_processes(self, _mock_detect):
        """get_processes() sobre un env_id inexistente lanza EnvironmentNotFoundError."""
        from docker.errors import NotFound

        mock_client = MagicMock()
        mock_client.containers.get.side_effect = NotFound("not found")

        provider = DockerRootlessProvider(config=FlexiPwnConfig(), client=mock_client)

        with pytest.raises(EnvironmentNotFoundError):
            provider.get_processes("run-no-existe")

    @patch("flexipwn.layer1.docker_rootless._detect_socket", return_value="unix:///fake.sock")
    def test_provider_error_on_diff_api_failure(self, _mock_detect):
        """get_filesystem_diff() envuelve APIError en ProviderError."""
        from docker.errors import APIError

        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_container.diff.side_effect = APIError("docker daemon error")
        mock_client.containers.get.return_value = mock_container

        provider = DockerRootlessProvider(config=FlexiPwnConfig(), client=mock_client)

        with pytest.raises(ProviderError, match="diff del filesystem"):
            provider.get_filesystem_diff("run-abcd1234")


class TestGetFilesystemDiff:
    @patch("flexipwn.layer1.docker_rootless._detect_socket", return_value="unix:///fake.sock")
    def test_returns_parsed_list(self, _mock_detect):
        """get_filesystem_diff() parsea correctamente la salida de container.diff()."""
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_container.diff.return_value = [{"Kind": 1, "Path": "/root/pwned.txt"}]
        mock_client.containers.get.return_value = mock_container

        provider = DockerRootlessProvider(config=FlexiPwnConfig(), client=mock_client)
        result = provider.get_filesystem_diff("run-abcd1234")

        assert result == [{"kind": 1, "path": "/root/pwned.txt"}]


class TestWaitForHealthy:
    @patch("flexipwn.layer1.docker_rootless._detect_socket", return_value="unix:///fake.sock")
    def test_returns_no_health_when_no_healthcheck(self, _mock_detect):
        """_wait_for_healthy() retorna 'no_health' si el contenedor no tiene HEALTHCHECK."""
        mock_client = MagicMock()
        provider = DockerRootlessProvider(config=FlexiPwnConfig(), client=mock_client)

        mock_container = MagicMock()
        mock_container.attrs = {"State": {}}  # sin clave "Health"

        result = provider._wait_for_healthy(
            mock_container, timeout=5.0, poll_interval=1.0
        )

        assert result == "no_health"

    @patch("flexipwn.layer1.docker_rootless.time.sleep")
    @patch("flexipwn.layer1.docker_rootless._detect_socket", return_value="unix:///fake.sock")
    def test_returns_timeout_after_limit(self, _mock_detect, _mock_sleep):
        """_wait_for_healthy() retorna 'timeout' si el contenedor nunca llega a healthy."""
        mock_client = MagicMock()
        config = FlexiPwnConfig(healthcheck_timeout=3.0, healthcheck_poll_interval=1.0)
        provider = DockerRootlessProvider(config=config, client=mock_client)

        mock_container = MagicMock()
        # Health presente pero siempre en "starting"
        mock_container.attrs = {"State": {"Health": {"Status": "starting"}}}

        result = provider._wait_for_healthy(
            mock_container, timeout=3.0, poll_interval=1.0
        )

        assert result == "timeout"

    @patch("flexipwn.layer1.docker_rootless.time.sleep")
    @patch("flexipwn.layer1.docker_rootless._detect_socket", return_value="unix:///fake.sock")
    def test_create_passes_yaml_delay_to_baseline(self, _mock_detect, mock_sleep, tmp_path):
        """create() con startup_delay=7.0 duerme 1s inicial + 6s restantes."""
        mock_client = MagicMock()
        config = FlexiPwnConfig(
            volumes_base_path=str(tmp_path / "vols"),
            startup_delay_seconds=3.0,
        )

        # Contenedor sin healthcheck
        mock_container = MagicMock()
        mock_container.attrs = {"State": {}}
        mock_container.diff.return_value = []
        mock_client.containers.get.return_value = mock_container

        provider = DockerRootlessProvider(config=config, client=mock_client)
        env = provider.create(
            scenario_id="test",
            participant_id="student-1",
            image="ubuntu:22.04",
            startup_delay=7.0,
        )

        assert env.baseline_strategy == "delay"
        sleep_calls = [call.args[0] for call in mock_sleep.call_args_list]
        assert 1.0 in sleep_calls   # sleep inicial obligatorio
        assert 6.0 in sleep_calls   # remaining = 7.0 - 1.0


# ---------------------------------------------------------------------------
# TestGetProcesses — árbol de procesos con dos llamadas a top()
# ---------------------------------------------------------------------------


def _make_process_info(pid, euid, ppid, cmd, lstart="", ppid_cmd="", ancestor_cmds=None):
    process_id = make_process_id(pid, lstart) if lstart else make_process_id(pid, cmd)
    return ProcessInfo(
        pid=pid, euid=euid, ppid=ppid, cmd=cmd,
        lstart=lstart, process_id=process_id,
        ppid_cmd=ppid_cmd, ancestor_cmds=ancestor_cmds or [],
    )


@patch("flexipwn.layer1.docker_rootless._detect_socket", return_value="unix:///fake.sock")
class TestGetProcesses:

    def _make_provider_with_top(self, _mock_detect, top_lstart_rows, top_info_rows):
        mock_client = MagicMock()
        mock_container = MagicMock()
        # Primera llamada: lstart; segunda: info
        mock_container.top.side_effect = [
            {"Titles": ["PID", "STARTED"], "Processes": top_lstart_rows},
            {"Titles": ["PID", "EUID", "PPID", "CMD"], "Processes": top_info_rows},
        ]
        mock_client.containers.get.return_value = mock_container
        return DockerRootlessProvider(config=FlexiPwnConfig(), client=mock_client)

    def test_get_processes_two_top_calls(self, _mock_detect):
        """get_processes() hace exactamente dos llamadas a top() y rellena lstart."""
        provider = self._make_provider_with_top(
            _mock_detect,
            top_lstart_rows=[
                ["1",   "Mon", "Oct", "23", "10:25:44", "2023"],
                ["100", "Mon", "Oct", "23", "10:30:00", "2023"],
            ],
            top_info_rows=[
                ["1",   "0", "0", "init"],
                ["100", "0", "1", "bash"],
            ],
        )

        results = provider.get_processes("run-abcd1234")

        assert len(results) == 2
        by_pid = {p.pid: p for p in results}
        p100 = by_pid["100"]
        assert p100.lstart == "Mon Oct 23 10:30:00 2023"
        assert p100.process_id == make_process_id("100", "Mon Oct 23 10:30:00 2023")
        assert len(p100.process_id) == 12

    def test_get_processes_resolves_ppid_cmd(self, _mock_detect):
        """ppid_cmd se rellena con el cmd del proceso padre."""
        provider = self._make_provider_with_top(
            _mock_detect,
            top_lstart_rows=[
                ["42",  "Mon", "Oct", "23", "10:00:00", "2023"],
                ["100", "Mon", "Oct", "23", "10:30:00", "2023"],
            ],
            top_info_rows=[
                ["42",  "0", "1", "vim", "/etc/hosts"],
                ["100", "0", "42", "bash"],
            ],
        )

        results = provider.get_processes("run-abcd1234")
        by_pid = {p.pid: p for p in results}

        assert by_pid["100"].ppid_cmd == "vim /etc/hosts"
        assert by_pid["42"].ppid_cmd == ""   # padre PID 1 no existe en esta muestra

    def test_get_processes_resolves_ancestor_chain(self, _mock_detect):
        """ancestor_cmds contiene la cadena [padre, abuelo, ...] del proceso."""
        provider = self._make_provider_with_top(
            _mock_detect,
            top_lstart_rows=[
                ["1",   "Mon", "Oct", "23", "10:00:00", "2023"],
                ["30",  "Mon", "Oct", "23", "10:10:00", "2023"],
                ["42",  "Mon", "Oct", "23", "10:20:00", "2023"],
                ["100", "Mon", "Oct", "23", "10:30:00", "2023"],
            ],
            top_info_rows=[
                ["1",   "0", "0", "bash"],
                ["30",  "0", "1", "sudo vim"],
                ["42",  "0", "30", "vim /etc/hosts"],
                ["100", "0", "42", "bash"],
            ],
        )

        results = provider.get_processes("run-abcd1234")
        by_pid = {p.pid: p for p in results}

        # bash(100) → vim(42) → sudo vim(30) → bash(1)
        assert by_pid["100"].ancestor_cmds == ["vim /etc/hosts", "sudo vim", "bash"]

    def test_ancestor_resolution_handles_cycle(self, _mock_detect):
        """Un proceso con ppid apuntando a sí mismo no causa bucle infinito."""
        # Simular un proceso con self-reference en ppid
        by_pid_mock = {
            "1": ProcessInfo(
                pid="1", euid=0, ppid="1", cmd="init",
                lstart="", process_id="aaa",
                ppid_cmd="", ancestor_cmds=[],
            )
        }
        result = _resolve_ancestors("1", by_pid_mock)
        assert result == []

    def test_ancestor_resolution_handles_mutual_cycle(self, _mock_detect):
        """Ciclo A→B→A no causa bucle infinito."""
        by_pid_mock = {
            "A": ProcessInfo(
                pid="A", euid=0, ppid="B", cmd="procA",
                lstart="", process_id="aaa",
                ppid_cmd="", ancestor_cmds=[],
            ),
            "B": ProcessInfo(
                pid="B", euid=0, ppid="A", cmd="procB",
                lstart="", process_id="bbb",
                ppid_cmd="", ancestor_cmds=[],
            ),
        }
        result = _resolve_ancestors("A", by_pid_mock)
        # Visita B (agrega "procB"), luego A (agrega "procA"),
        # luego intenta B de nuevo (ya visitado) → para
        assert result == ["procB", "procA"]
