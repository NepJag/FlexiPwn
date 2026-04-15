"""Tests de integración — requieren Docker rootless disponible."""

import subprocess
import textwrap

import pytest

from flexipwn.config import FlexiPwnConfig
from flexipwn.layer1.docker_rootless import DockerRootlessProvider
from flexipwn.layer1.provider import ContainerStartError, ExecResult, ProcessInfo

pytestmark = pytest.mark.integration

TEST_IMAGE = "ubuntu:22.04"


def _build_image(tag: str, dockerfile_content: str) -> None:
    """Construye una imagen Docker a partir de un Dockerfile inline."""
    result = subprocess.run(
        ["docker", "build", "-t", tag, "-f", "-", "."],
        input=dockerfile_content.encode(),
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"docker build falló para '{tag}':\n{result.stderr.decode()}"
        )


@pytest.fixture
def provider(tmp_path):
    config = FlexiPwnConfig(volumes_base_path=str(tmp_path / "flexipwn-vols"))
    p = DockerRootlessProvider(config=config)
    yield p
    # Cleanup de emergencia por si un test falla
    p.cleanup_all()


@pytest.fixture
def env(provider):
    environment = provider.create(
        scenario_id="integration-test",
        participant_id="tester-1",
        image=TEST_IMAGE,
    )
    yield environment
    try:
        provider.destroy(environment.env_id)
    except Exception:
        pass


class TestCreateAndDestroy:
    def test_create_and_destroy(self, provider, tmp_path):
        env = provider.create(
            scenario_id="test-cd",
            participant_id="student-1",
            image=TEST_IMAGE,
        )

        assert env.env_id.startswith("run-")
        assert env.status == "running"
        assert env.container_vulnerable_name == f"flexipwn-{env.env_id}-vulnerable"
        assert env.container_attacker_name is None
        assert env.network_name == f"flexipwn-{env.env_id}"

        # Verificar que los contenedores existen
        status = provider.get_status(env.env_id)
        assert status.status == "running"

        # Destruir
        provider.destroy(env.env_id)

        with pytest.raises(Exception):
            provider.get_status(env.env_id)


class TestGetProcesses:
    def test_returns_list(self, provider, env):
        processes = provider.get_processes(env.env_id)
        assert isinstance(processes, list)
        # Al menos el proceso init/shell del contenedor
        assert len(processes) >= 1
        for p in processes:
            assert isinstance(p, ProcessInfo)
            assert p.pid
            assert isinstance(p.euid, int)
            assert p.cmd

    def test_get_processes_parsed_correctly(self, provider):
        """
        Verifica que el parsing de get_processes() produce ProcessInfo válidos:
        process_id de 12 caracteres hexadecimales y campos no vacíos.

        Nota: lstart es "" porque container.top() limita columnas a len(Titles)
        y usar lstart causaría overflow que mezcla campos.
        """
        env = provider.create(
            scenario_id="test-parsing",
            participant_id="tester-parsing",
            image=TEST_IMAGE,
        )
        try:
            processes = provider.get_processes(env.env_id)
            assert len(processes) >= 1

            hex_chars = set("0123456789abcdef")
            for p in processes:
                assert p.pid, f"pid vacío"
                assert p.cmd, f"cmd vacío para pid={p.pid}"
                assert p.lstart == "", f"lstart debe ser '' (no disponible vía top)"
                assert len(p.process_id) == 12, (
                    f"process_id tiene longitud {len(p.process_id)}, esperado 12"
                )
                assert all(c in hex_chars for c in p.process_id), (
                    f"process_id no es hexadecimal: {p.process_id!r}"
                )
        finally:
            provider.destroy(env.env_id)


class TestExecRun:
    def test_returns_output(self, provider, env):
        result = provider.exec_run(env.env_id, "echo hello")
        assert isinstance(result, ExecResult)
        assert result.exit_code == 0
        assert "hello" in result.stdout


class TestReset:
    def test_preserves_env_id(self, provider, env):
        original_id = env.env_id
        provider.reset(env.env_id)

        status = provider.get_status(original_id)
        assert status.env_id == original_id
        assert status.status == "running"


class TestFilesystemDiff:
    def test_detects_created_file(self, provider):
        env = provider.create(
            scenario_id="test-diff",
            participant_id="tester-1",
            image=TEST_IMAGE,
        )
        try:
            provider.exec_run(env.env_id, "bash -c 'echo pwned > /root/test.txt'")

            diff = provider.get_filesystem_diff(env.env_id)

            assert isinstance(diff, list)
            paths = [entry["path"] for entry in diff]
            assert "/root/test.txt" in paths

            created = [e for e in diff if e["path"] == "/root/test.txt"]
            assert created[0]["kind"] == 1  # kind 1 = creado
        finally:
            provider.destroy(env.env_id)


class TestBaselineStrategy:
    HEALTHY_IMAGE = "flexipwn-test-healthy:latest"
    UNHEALTHY_IMAGE = "flexipwn-test-unhealthy:latest"

    @pytest.fixture(autouse=True, scope="class")
    def build_test_images(self):
        """Construye las imágenes mínimas necesarias para los tests de baseline."""
        _build_image(
            self.HEALTHY_IMAGE,
            textwrap.dedent("""\
                FROM ubuntu:22.04
                HEALTHCHECK --interval=1s --timeout=1s --retries=3 CMD exit 0
                CMD ["sleep", "infinity"]
            """),
        )
        _build_image(
            self.UNHEALTHY_IMAGE,
            textwrap.dedent("""\
                FROM ubuntu:22.04
                HEALTHCHECK --interval=1s --timeout=1s --retries=1 CMD exit 1
                CMD ["sleep", "infinity"]
            """),
        )

    def test_create_with_healthcheck_uses_healthy_strategy(self, provider):
        """Si la imagen tiene HEALTHCHECK válido, baseline_strategy debe ser 'healthcheck'."""
        env = provider.create(
            scenario_id="test-hc",
            participant_id="tester-1",
            image=self.HEALTHY_IMAGE,
        )
        try:
            assert env.baseline_strategy == "healthcheck"
        finally:
            provider.destroy(env.env_id)

    def test_create_without_healthcheck_uses_delay_strategy(self, provider):
        """ubuntu:22.04 no tiene HEALTHCHECK, baseline_strategy debe ser 'delay'."""
        config = FlexiPwnConfig(
            volumes_base_path=provider.config.volumes_base_path,
            startup_delay_seconds=2.0,  # delay corto para el test
        )
        p = DockerRootlessProvider(config=config)
        env = p.create(
            scenario_id="test-delay",
            participant_id="tester-1",
            image=TEST_IMAGE,
        )
        try:
            assert env.baseline_strategy == "delay"
        finally:
            p.destroy(env.env_id)

    def test_create_unhealthy_raises_container_start_error(self, provider):
        """Imagen con HEALTHCHECK CMD exit 1 debe lanzar ContainerStartError."""
        with pytest.raises(ContainerStartError, match="unhealthy"):
            env = provider.create(
                scenario_id="test-unhealthy",
                participant_id="tester-1",
                image=self.UNHEALTHY_IMAGE,
            )
            provider.destroy(env.env_id)
