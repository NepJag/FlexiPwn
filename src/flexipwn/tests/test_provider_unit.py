"""Tests unitarios para Layer 1 — no requieren Docker."""

from unittest.mock import MagicMock, patch

import pytest

from flexipwn.config import FlexiPwnConfig
from flexipwn.layer1.docker_rootless import (
    DockerRootlessProvider,
    _generate_env_id,
)
from flexipwn.layer1.provider import (
    ContainerStartError,
    EnvironmentNotFoundError,
    ImageNotFoundError,
    ProviderError,
    SocketNotFoundError,
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
    @patch("flexipwn.layer1.docker_rootless._detect_socket", return_value="unix:///fake.sock")
    def test_create_does_not_mount_system_dirs(self, _mock_detect, tmp_path):
        """create() no debe montar /etc, /root ni /home como bind mounts."""
        mock_client = MagicMock()
        config = FlexiPwnConfig(volumes_base_path=str(tmp_path / "vols"))

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
