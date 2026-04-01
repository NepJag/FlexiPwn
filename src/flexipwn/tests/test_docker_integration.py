"""Tests de integración — requieren Docker rootless disponible."""

import pytest

from flexipwn.config import FlexiPwnConfig
from flexipwn.layer1.docker_rootless import DockerRootlessProvider
from flexipwn.layer1.provider import ExecResult, ProcessInfo

pytestmark = pytest.mark.integration

TEST_IMAGE = "ubuntu:22.04"


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
