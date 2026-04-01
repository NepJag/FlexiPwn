from __future__ import annotations

import logging
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

import docker
from docker.errors import APIError, ImageNotFound, NotFound

from flexipwn.config import FlexiPwnConfig
from flexipwn.layer1.provider import (
    ContainerStartError,
    Environment,
    EnvironmentNotFoundError,
    EnvironmentProvider,
    ExecResult,
    ImageNotFoundError,
    ProcessInfo,
    ProviderError,
    SocketNotFoundError,
)

logger = logging.getLogger(__name__)

LABEL_MANAGED = "flexipwn.managed"
LABEL_ENV_ID = "flexipwn.env_id"
LABEL_SCENARIO_ID = "flexipwn.scenario_id"
LABEL_PARTICIPANT_ID = "flexipwn.participant_id"


def _generate_env_id() -> str:
    return f"run-{uuid.uuid4().hex[:8]}"


def _detect_socket() -> str:
    """Detecta el socket Docker rootless en orden de prioridad."""
    # 1. DOCKER_HOST
    docker_host = os.environ.get("DOCKER_HOST")
    if docker_host:
        return docker_host

    # 2. $XDG_RUNTIME_DIR/docker.sock
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        sock = os.path.join(xdg, "docker.sock")
        if os.path.exists(sock):
            return f"unix://{sock}"

    # 3. /run/user/{uid}/docker.sock
    try:
        uid = os.getuid()
    except AttributeError:
        # Windows no tiene os.getuid(); el socket rootless no aplica.
        raise SocketNotFoundError(
            "os.getuid() no disponible en esta plataforma. "
            "Configura docker_socket en FlexiPwnConfig o la variable DOCKER_HOST."
        )

    fallback = f"/run/user/{uid}/docker.sock"
    if os.path.exists(fallback):
        return f"unix://{fallback}"

    raise SocketNotFoundError(
        "No se encontró un socket Docker rootless. "
        "Verifica que Docker rootless esté corriendo o configura DOCKER_HOST."
    )


class DockerRootlessProvider(EnvironmentProvider):

    def __init__(
        self,
        config: FlexiPwnConfig | None = None,
        client: docker.DockerClient | None = None,
    ) -> None:
        self.config = config or FlexiPwnConfig()

        if client is not None:
            self.client = client
        else:
            socket_url = self.config.docker_socket or _detect_socket()
            self.client = docker.DockerClient(base_url=socket_url)

    # ------------------------------------------------------------------
    # Helpers internos
    # ------------------------------------------------------------------

    def _labels(
        self, env_id: str, scenario_id: str, participant_id: str
    ) -> dict[str, str]:
        return {
            LABEL_MANAGED: "true",
            LABEL_ENV_ID: env_id,
            LABEL_SCENARIO_ID: scenario_id,
            LABEL_PARTICIPANT_ID: participant_id,
        }

    def _volume_base(self, env_id: str) -> Path:
        return Path(self.config.volumes_base_path) / env_id

    def _container_name(self, env_id: str, role: str) -> str:
        return f"flexipwn-{env_id}-{role}"

    def _network_name(self, env_id: str) -> str:
        return f"flexipwn-{env_id}"

    def _get_container(self, env_id: str, role: str = "vulnerable"):
        name = self._container_name(env_id, role)
        try:
            return self.client.containers.get(name)
        except NotFound:
            raise EnvironmentNotFoundError(
                f"Contenedor '{name}' no encontrado. "
                f"El entorno '{env_id}' no existe o ya fue destruido."
            )

    # ------------------------------------------------------------------
    # EnvironmentProvider
    # ------------------------------------------------------------------

    def create(
        self,
        scenario_id: str,
        participant_id: str,
        image: str,
        attacker_image: str | None = None,
        ports: list[str] | None = None,
        timeout_seconds: int = 1800,
    ) -> Environment:
        env_id = _generate_env_id()
        labels = self._labels(env_id, scenario_id, participant_id)
        net_name = self._network_name(env_id)
        vol_base = self._volume_base(env_id)

        # Recursos creados (para rollback)
        created_dirs = False
        created_network = False
        created_vulnerable = False

        try:
            # 1. Directorio base de volúmenes (alojará logs en el futuro)
            vol_base.mkdir(parents=True, exist_ok=True)
            os.chmod(vol_base, 0o700)
            (vol_base / "logs").mkdir(exist_ok=True)
            created_dirs = True

            # 2. Red interna
            self.client.networks.create(
                net_name, driver="bridge", internal=True, labels=labels
            )
            created_network = True

            # 3. Contenedor vulnerable (sin bind mounts de filesystem)
            vuln_name = self._container_name(env_id, "vulnerable")
            try:
                self.client.containers.run(
                    image,
                    name=vuln_name,
                    network=net_name,
                    labels=labels,
                    detach=True,
                    stdin_open=True,  # mantiene el contenedor vivo
                    stop_signal="SIGTERM",
                )
            except ImageNotFound:
                raise ImageNotFoundError(f"Imagen '{image}' no encontrada.")
            except APIError as exc:
                raise ContainerStartError(
                    f"Error al iniciar contenedor vulnerable: {exc}"
                )
            created_vulnerable = True

            # 4. Contenedor atacante (opcional)
            attacker_name: str | None = None
            if attacker_image is not None:
                attacker_name = self._container_name(env_id, "attacker")
                try:
                    self.client.containers.run(
                        attacker_image,
                        name=attacker_name,
                        network=net_name,
                        labels=labels,
                        detach=True,
                        stdin_open=True,
                        stop_signal="SIGTERM",
                    )
                except ImageNotFound:
                    raise ImageNotFoundError(
                        f"Imagen atacante '{attacker_image}' no encontrada."
                    )
                except APIError as exc:
                    raise ContainerStartError(
                        f"Error al iniciar contenedor atacante: {exc}"
                    )

            return Environment(
                env_id=env_id,
                scenario_id=scenario_id,
                participant_id=participant_id,
                container_vulnerable_name=vuln_name,
                container_attacker_name=attacker_name,
                network_name=net_name,
                status="running",
                created_at=datetime.now(timezone.utc),
                volume_base_path=str(vol_base),
                volume_mappings={},
            )

        except Exception:
            # Rollback: limpiar todo lo que se haya creado parcialmente
            self._rollback(env_id, created_vulnerable, created_network, created_dirs)
            raise

    def _rollback(
        self,
        env_id: str,
        has_vulnerable: bool,
        has_network: bool,
        has_dirs: bool,
    ) -> None:
        """Limpia recursos creados parcialmente durante un create() fallido."""
        # Contenedor atacante (puede existir o no)
        try:
            c = self.client.containers.get(
                self._container_name(env_id, "attacker")
            )
            c.remove(force=True)
        except NotFound:
            pass
        except Exception as exc:
            logger.warning("Rollback: error eliminando atacante: %s", exc)

        if has_vulnerable:
            try:
                c = self.client.containers.get(
                    self._container_name(env_id, "vulnerable")
                )
                c.remove(force=True)
            except NotFound:
                pass
            except Exception as exc:
                logger.warning("Rollback: error eliminando vulnerable: %s", exc)

        if has_network:
            try:
                net = self.client.networks.get(self._network_name(env_id))
                net.remove()
            except NotFound:
                pass
            except Exception as exc:
                logger.warning("Rollback: error eliminando red: %s", exc)

        if has_dirs:
            vol_base = self._volume_base(env_id)
            shutil.rmtree(vol_base, ignore_errors=True)

    def destroy(self, env_id: str) -> None:
        timeout = self.config.container_stop_timeout

        # Contenedores
        for role in ("vulnerable", "attacker"):
            name = self._container_name(env_id, role)
            try:
                c = self.client.containers.get(name)
                c.stop(timeout=timeout)
                c.remove(force=True)
            except NotFound:
                pass

        # Red
        try:
            net = self.client.networks.get(self._network_name(env_id))
            net.remove()
        except NotFound:
            pass

        # Volúmenes (directorios)
        vol_base = self._volume_base(env_id)
        if vol_base.exists():
            shutil.rmtree(vol_base)

    def reset(self, env_id: str) -> None:
        # Obtener info del contenedor vulnerable actual
        vuln = self._get_container(env_id, "vulnerable")
        image = vuln.image.tags[0] if vuln.image.tags else vuln.image.id
        labels = vuln.labels
        scenario_id = labels.get(LABEL_SCENARIO_ID, "")
        participant_id = labels.get(LABEL_PARTICIPANT_ID, "")

        # Obtener info del atacante si existe
        attacker_image: str | None = None
        try:
            atk = self.client.containers.get(
                self._container_name(env_id, "attacker")
            )
            attacker_image = (
                atk.image.tags[0] if atk.image.tags else atk.image.id
            )
        except NotFound:
            pass

        timeout = self.config.container_stop_timeout

        # Detener y eliminar contenedores
        for role in ("vulnerable", "attacker"):
            try:
                c = self.client.containers.get(
                    self._container_name(env_id, role)
                )
                c.stop(timeout=timeout)
                c.remove(force=True)
            except NotFound:
                pass

        all_labels = self._labels(env_id, scenario_id, participant_id)
        net_name = self._network_name(env_id)

        # Recrear contenedor vulnerable (sin bind mounts)
        try:
            self.client.containers.run(
                image,
                name=self._container_name(env_id, "vulnerable"),
                network=net_name,
                labels=all_labels,
                detach=True,
                stdin_open=True,
                stop_signal="SIGTERM",
            )
        except APIError as exc:
            raise ContainerStartError(
                f"Error al reiniciar contenedor vulnerable: {exc}"
            )

        # Recrear contenedor atacante si existía
        if attacker_image is not None:
            try:
                self.client.containers.run(
                    attacker_image,
                    name=self._container_name(env_id, "attacker"),
                    network=net_name,
                    labels=all_labels,
                    detach=True,
                    stdin_open=True,
                    stop_signal="SIGTERM",
                )
            except APIError as exc:
                raise ContainerStartError(
                    f"Error al reiniciar contenedor atacante: {exc}"
                )

    def get_status(self, env_id: str) -> Environment:
        vuln = self._get_container(env_id, "vulnerable")
        labels = vuln.labels

        # Verificar atacante
        attacker_name: str | None = None
        try:
            self.client.containers.get(
                self._container_name(env_id, "attacker")
            )
            attacker_name = self._container_name(env_id, "attacker")
        except NotFound:
            pass

        # Estado basado en el contenedor vulnerable
        docker_status = vuln.status  # "running", "exited", etc.
        status = "running" if docker_status == "running" else "stopped"

        vol_base = self._volume_base(env_id)

        # TODO: created_at no se persiste en labels; usar fecha actual como aproximación
        created_str = vuln.attrs.get("Created", "")
        try:
            created_at = datetime.fromisoformat(
                created_str.replace("Z", "+00:00")
            )
        except (ValueError, AttributeError):
            created_at = datetime.now(timezone.utc)

        return Environment(
            env_id=env_id,
            scenario_id=labels.get(LABEL_SCENARIO_ID, ""),
            participant_id=labels.get(LABEL_PARTICIPANT_ID, ""),
            container_vulnerable_name=self._container_name(env_id, "vulnerable"),
            container_attacker_name=attacker_name,
            network_name=self._network_name(env_id),
            status=status,
            created_at=created_at,
            volume_base_path=str(vol_base),
            volume_mappings={},
        )

    def exec_run(
        self,
        env_id: str,
        cmd: str,
        user: str = "root",
        container: str = "vulnerable",
    ) -> ExecResult:
        c = self._get_container(env_id, container)
        result = c.exec_run(cmd, user=user, demux=True)
        stdout = result.output[0].decode("utf-8", errors="replace") if result.output[0] else ""
        stderr = result.output[1].decode("utf-8", errors="replace") if result.output[1] else ""
        return ExecResult(
            exit_code=result.exit_code,
            stdout=stdout,
            stderr=stderr,
        )

    def get_filesystem_diff(self, env_id: str) -> list[dict]:
        """
        Retorna los cambios en el filesystem del contenedor respecto a su imagen.
        Usa container.diff() — completamente externo, sin exec, sin bind mounts.

        Retorna lista de dicts: [{"kind": int, "path": str}, ...]
        kind: 0 = modificado, 1 = creado, 2 = eliminado

        Esta función es consumida por el Monitor de filesystem de Capa 2.
        """
        c = self._get_container(env_id, "vulnerable")
        try:
            diff = c.diff()
        except APIError as exc:
            raise ProviderError(f"Error obteniendo diff del filesystem: {exc}")
        if diff is None:
            return []
        return [{"kind": item["Kind"], "path": item["Path"]} for item in diff]

    def get_processes(self, env_id: str) -> list[ProcessInfo]:
        c = self._get_container(env_id, "vulnerable")
        try:
            top_result = c.top(ps_args="-eo pid,ppid,euid,cmd")
        except APIError as exc:
            raise ProviderError(f"Error obteniendo procesos: {exc}")

        processes: list[ProcessInfo] = []
        for row in top_result.get("Processes", []):
            # Cada row es una lista: [pid, ppid, euid, cmd]
            if len(row) < 4:
                continue
            processes.append(
                ProcessInfo(
                    pid=row[0].strip(),
                    ppid=row[1].strip(),
                    euid=int(row[2].strip()),
                    cmd=" ".join(row[3:]).strip(),
                )
            )
        return processes

    def cleanup_all(self) -> None:
        """Elimina TODOS los recursos de FlexiPwn (emergencia)."""
        # Contenedores
        containers = self.client.containers.list(
            all=True, filters={"label": f"{LABEL_MANAGED}=true"}
        )
        for c in containers:
            try:
                c.remove(force=True)
            except Exception as exc:
                logger.warning("cleanup_all: error eliminando contenedor %s: %s", c.name, exc)

        # Redes
        networks = self.client.networks.list(
            filters={"label": f"{LABEL_MANAGED}=true"}
        )
        for net in networks:
            try:
                net.remove()
            except Exception as exc:
                logger.warning("cleanup_all: error eliminando red %s: %s", net.name, exc)

        # Directorios de volúmenes
        base = Path(self.config.volumes_base_path)
        if base.exists():
            shutil.rmtree(base, ignore_errors=True)
