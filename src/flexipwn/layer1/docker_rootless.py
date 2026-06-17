from __future__ import annotations

import json
import logging
import os
import shutil
import time
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
    make_process_id,
)

logger = logging.getLogger(__name__)

LABEL_MANAGED = "flexipwn.managed"
LABEL_ENV_ID = "flexipwn.env_id"
LABEL_SCENARIO_ID = "flexipwn.scenario_id"
LABEL_PARTICIPANT_ID = "flexipwn.participant_id"
LABEL_CAPTURE_FILTER = "flexipwn.capture_filter"

SNIFFER_IMAGE = "nicolaka/netshoot"


def _generate_env_id() -> str:
    return f"run-{uuid.uuid4().hex[:8]}"


def _resolve_ancestors(
    pid: str,
    by_pid: dict,
    max_depth: int = 10,
) -> list[str]:
    """Recorre el árbol de procesos via PPID y retorna los cmds de los ancestros.

    Retorna lista ordenada del padre más cercano al más lejano.
    Termina al alcanzar un PID sin entrada, PID 0, o un ciclo.
    """
    chain: list[str] = []
    current_pid = pid
    visited: set[str] = set()
    for _ in range(max_depth):
        current_info = by_pid.get(current_pid)
        if current_info is None:
            break
        parent_pid = current_info.ppid
        if parent_pid in visited or parent_pid == current_pid:
            break
        visited.add(parent_pid)
        parent = by_pid.get(parent_pid)
        if parent:
            chain.append(parent.cmd)
        current_pid = parent_pid
    return chain


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

    # macOS Docker Desktop socket
    mac_socket = Path.home() / ".docker" / "run" / "docker.sock"
    if mac_socket.exists():
        return f"unix://{mac_socket}"

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

        self._baselines: dict[str, set[str]] = {}
        self._baseline_strategies: dict[str, str] = {}

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

    def _state_dir(self, env_id: str) -> Path:
        return Path.home() / ".flexipwn" / "state" / env_id

    def _baseline_path(self, env_id: str) -> Path:
        return self._state_dir(env_id) / "baseline.json"

    def _persist_baseline(self, env_id: str) -> None:
        state = self._state_dir(env_id)
        state.mkdir(parents=True, exist_ok=True)
        payload = {
            "baseline": sorted(self._baselines.get(env_id, set())),
            "strategy": self._baseline_strategies.get(env_id, "unknown"),
        }
        self._baseline_path(env_id).write_text(json.dumps(payload))

    def _load_baseline(self, env_id: str) -> bool:
        path = self._baseline_path(env_id)
        if not path.exists():
            return False
        try:
            payload = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return False
        self._baselines[env_id] = set(payload.get("baseline", []))
        self._baseline_strategies[env_id] = payload.get("strategy", "unknown")
        return True

    def _container_name(self, env_id: str, role: str) -> str:
        return f"flexipwn-{env_id}-{role}"

    def _network_name(self, env_id: str) -> str:
        """Nombre de la red interna (vulnerable ↔ attacker, sin egress)."""
        return f"flexipwn-{env_id}"

    def _external_network_name(self, env_id: str) -> str:
        """Nombre de la red externa (attacker ↔ host, port bindings)."""
        return f"flexipwn-{env_id}-ext"

    def _create_network(self, env_id: str) -> tuple[str, str]:
        """
        Crea dos redes para el entorno:
        - Interna (internal=True): vulnerable ↔ attacker. Sin egress al host.
        - Externa (internal=False): attacker ↔ host. Habilita port bindings.

        Retorna (internal_net_name, external_net_name).
        """
        base_labels = {
            LABEL_MANAGED: "true",
            LABEL_ENV_ID: env_id,
        }
        internal_name = self._network_name(env_id)
        self.client.networks.create(
            internal_name,
            driver="bridge",
            internal=True,
            check_duplicate=True,
            labels=base_labels,
        )
        external_name = self._external_network_name(env_id)
        self.client.networks.create(
            external_name,
            driver="bridge",
            internal=False,
            check_duplicate=True,
            labels=base_labels,
        )
        return internal_name, external_name

    def _destroy_network(self, env_id: str) -> None:
        """Elimina ambas redes del entorno (interna y externa)."""
        for net_name in (self._network_name(env_id), self._external_network_name(env_id)):
            try:
                net = self.client.networks.get(net_name)
                net.remove()
            except NotFound:
                pass
            except Exception as exc:
                logger.warning("Error eliminando red %s: %s", net_name, exc)

    def _wait_for_healthy(
        self,
        container,
        timeout: float,
        poll_interval: float,
    ) -> str:
        """
        Espera hasta que el contenedor reporte status 'healthy'.

        Retorna:
          "healthy"   → llegó a healthy dentro del timeout
          "timeout"   → se agotó el timeout sin llegar a healthy
          "no_health" → el contenedor no tiene HEALTHCHECK configurado

        Lanza ContainerStartError si el status es "unhealthy".
        """
        container.reload()
        health = container.attrs.get("State", {}).get("Health")
        if not health:
            return "no_health"

        elapsed = 0.0
        while elapsed < timeout:
            container.reload()
            status = container.attrs["State"]["Health"]["Status"]
            if status == "healthy":
                return "healthy"
            if status == "unhealthy":
                raise ContainerStartError(
                    f"El contenedor '{container.name}' reportó status 'unhealthy'. "
                    f"Revisa el HEALTHCHECK del Dockerfile."
                )
            time.sleep(poll_interval)
            elapsed += poll_interval

        return "timeout"

    def _capture_dir(self, env_id: str) -> Path:
        return self._volume_base(env_id) / "capture"

    def _create_sniffer(self, env_id: str, capture_filter: str = "") -> None:
        capture_dir = self._capture_dir(env_id)
        capture_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(capture_dir, 0o700)
        vuln_name = self._container_name(env_id, "vulnerable")
        sniffer_name = self._container_name(env_id, "sniffer")
        # AppArmor adjunta el perfil 'tcpdump' del host por la RUTA del binario
        # (/usr/*/tcpdump) y deniega recibir señales de rootlesskit, dejando el
        # sniffer imposible de detener. Copiándolo a /tmp/fpcap y ejecutándolo
        # desde ahí, la ruta no coincide con el perfil → corre sin confinar y
        # el teardown puede matarlo.
        prep = 'T=$(command -v tcpdump); cp "$T" /tmp/fpcap'
        sniff = "exec /tmp/fpcap -i any -A -n -l 2>/dev/null"
        if capture_filter:
            sniff = f"{sniff} {capture_filter}"
        cmd = f"{prep}; {sniff} > /capture/traffic.txt"
        self.client.containers.run(
            SNIFFER_IMAGE,
            name=sniffer_name,
            network_mode=f"container:{vuln_name}",
            command=["sh", "-c", cmd],
            volumes={str(capture_dir): {"bind": "/capture", "mode": "rw"}},
            labels={
                LABEL_MANAGED: "true",
                LABEL_ENV_ID: env_id,
                LABEL_CAPTURE_FILTER: capture_filter,
            },
            detach=True,
            remove=False,
        )

    def _destroy_sniffer(self, env_id: str) -> None:
        name = self._container_name(env_id, "sniffer")
        try:
            c = self.client.containers.get(name)
            try:
                c.stop(timeout=self.config.container_stop_timeout)
            except Exception as exc:
                logger.warning("No se pudo detener sniffer %s, forzando remove: %s", name, exc)
            c.remove(force=True)
        except NotFound:
            pass
        except Exception as exc:
            logger.warning("Error eliminando sniffer %s: %s", name, exc)
        shutil.rmtree(self._capture_dir(env_id), ignore_errors=True)

    def get_capture_host_path(self, env_id: str) -> Path | None:
        capture_dir = self._capture_dir(env_id)
        if not capture_dir.exists():
            return None
        return capture_dir / "traffic.txt"

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
        attacker_ports: list[str] | None = None,
        log_paths: list[str] | None = None,
        timeout_seconds: int = 1800,
        startup_delay: float | None = None,
        enable_network_capture: bool = False,
        capture_filter: str = "",
    ) -> Environment:
        env_id = _generate_env_id()
        labels = self._labels(env_id, scenario_id, participant_id)
        vol_base = self._volume_base(env_id)

        # Recursos creados (para rollback)
        created_dirs = False
        created_network = False
        created_vulnerable = False
        created_sniffer = False

        try:
            # 1. Directorio base de volúmenes
            vol_base.mkdir(parents=True, exist_ok=True)
            os.chmod(vol_base, 0o700)
            (vol_base / "logs").mkdir(exist_ok=True)
            created_dirs = True

            # 1b. Preparar bind mounts para log_paths
            # Cada container_log_path se mapea al directorio padre en el host
            # preservando la ruta completa para evitar colisiones.
            log_volumes: dict[str, dict] = {}
            for container_log_path in (log_paths or []):
                container_dir = str(Path(container_log_path).parent)
                relative_dir = container_dir.lstrip("/")
                host_log_dir = vol_base / "logs" / relative_dir
                host_log_dir.mkdir(parents=True, exist_ok=True)
                os.chmod(host_log_dir, 0o777)
                log_volumes[str(host_log_dir)] = {"bind": container_dir, "mode": "rw"}

            # 1c. Parsear ports ["host:container"] → {container_port/tcp: host_port}
            #     Con bind_ip se publica en una sola interfaz:
            #       {container_port/tcp: (bind_ip, host_port)}
            #     docker-py acepta tanto el int (todas las interfaces) como la
            #     tupla (ip, puerto) para fijar la interfaz de publicación.
            def _parse_port_bindings(
                specs: list[str] | None,
                bind_ips: list[str] | None = None,
            ) -> dict[str, int | list[tuple[str, int]]]:
                bindings: dict[str, int | list[tuple[str, int]]] = {}
                for port_spec in (specs or []):
                    parts = port_spec.split(":")
                    if len(parts) == 2:
                        host_port, container_port = parts
                        key = f"{container_port}/tcp"
                        if bind_ips:
                            # Mismo puerto publicado en cada interfaz indicada.
                            bindings[key] = [(ip, int(host_port)) for ip in bind_ips]
                        else:
                            bindings[key] = int(host_port)
                return bindings

            # El vulnerable no publica nada; el atacante publica su SSH solo en
            # las interfaces elegidas (IP del DCC y/o la overlay netbird wt0),
            # nunca en la IP pública. attacker_bind_ips=None = todas (dev/local).
            port_bindings = _parse_port_bindings(ports)
            attacker_port_bindings = _parse_port_bindings(
                attacker_ports, bind_ips=self.config.attacker_bind_ips
            )

            # 2. Redes (interna para vuln↔attacker, externa para attacker↔host)
            internal_net_name, external_net_name = self._create_network(env_id)
            created_network = True

            # 3. Contenedor vulnerable — solo en la red interna (sin egress)
            vuln_name = self._container_name(env_id, "vulnerable")
            try:
                self.client.containers.run(
                    image,
                    name=vuln_name,
                    network=internal_net_name,
                    labels=labels,
                    detach=True,
                    stdin_open=True,  # mantiene el contenedor vivo
                    stop_signal="SIGTERM",
                    volumes=log_volumes if log_volumes else None,
                    ports=port_bindings if port_bindings else None,
                )
            except ImageNotFound:
                raise ImageNotFoundError(f"Imagen '{image}' no encontrada.")
            except APIError as exc:
                raise ContainerStartError(
                    f"Error al iniciar contenedor vulnerable: {exc}"
                )
            created_vulnerable = True

            # 4. Contenedor atacante (opcional) — arranca en la red externa
            # (no internal) para que Docker pueda publicar los port bindings
            # al host, y luego se conecta también a la red interna para
            # comunicarse con el vulnerable sin egress.
            attacker_name: str | None = None
            if attacker_image is not None:
                attacker_name = self._container_name(env_id, "attacker")
                try:
                    self.client.containers.run(
                        attacker_image,
                        name=attacker_name,
                        network=external_net_name,
                        labels=labels,
                        detach=True,
                        stdin_open=True,
                        stop_signal="SIGTERM",
                        ports=attacker_port_bindings if attacker_port_bindings else None,
                    )
                except ImageNotFound:
                    raise ImageNotFoundError(
                        f"Imagen atacante '{attacker_image}' no encontrada."
                    )
                except APIError as exc:
                    raise ContainerStartError(
                        f"Error al iniciar contenedor atacante: {exc}"
                    )

                int_net = self.client.networks.get(internal_net_name)
                int_net.connect(attacker_name)

            # 5. Baseline del filesystem con estrategia robusta
            effective_delay = (
                startup_delay
                if startup_delay is not None
                else self.config.startup_delay_seconds
            )

            # Espera mínima de 1s para que arranque el proceso principal
            time.sleep(1.0)

            vuln_container = self.client.containers.get(vuln_name)
            health_result = self._wait_for_healthy(
                vuln_container,
                timeout=self.config.healthcheck_timeout,
                poll_interval=self.config.healthcheck_poll_interval,
            )

            if health_result == "healthy":
                baseline_strategy = "healthcheck"
            elif health_result == "no_health":
                remaining = max(0.0, effective_delay - 1.0)
                if remaining > 0:
                    time.sleep(remaining)
                baseline_strategy = "delay"
            else:  # "timeout"
                logger.warning(
                    "El contenedor '%s' no reportó 'healthy' después de %.0fs. "
                    "El baseline se tomó igualmente. Considera aumentar "
                    "healthcheck_timeout en FlexiPwnConfig o revisar el HEALTHCHECK "
                    "del Dockerfile.",
                    vuln_name,
                    self.config.healthcheck_timeout,
                )
                baseline_strategy = "timeout"

            vuln_container.reload()
            baseline_diff = vuln_container.diff() or []
            self._baselines[env_id] = {item["Path"] for item in baseline_diff}
            self._baseline_strategies[env_id] = baseline_strategy
            self._persist_baseline(env_id)

            if enable_network_capture:
                self._create_sniffer(env_id, capture_filter=capture_filter)
                created_sniffer = True

            # volume_mappings: container_log_path → host_log_dir (directorio)
            volume_mappings = {
                container_log_path: str(
                    vol_base / "logs" / str(Path(container_log_path).parent).lstrip("/")
                )
                for container_log_path in (log_paths or [])
            }

            return Environment(
                env_id=env_id,
                scenario_id=scenario_id,
                participant_id=participant_id,
                container_vulnerable_name=vuln_name,
                container_attacker_name=attacker_name,
                network_name=internal_net_name,
                status="running",
                created_at=datetime.now(timezone.utc),
                volume_base_path=str(vol_base),
                volume_mappings=volume_mappings,
                baseline_strategy=baseline_strategy,
            )

        except Exception:
            # Rollback: limpiar todo lo que se haya creado parcialmente
            self._rollback(env_id, created_vulnerable, created_network, created_dirs, has_sniffer=created_sniffer)
            raise

    def _rollback(
        self,
        env_id: str,
        has_vulnerable: bool,
        has_network: bool,
        has_dirs: bool,
        has_sniffer: bool = False,
    ) -> None:
        """Limpia recursos creados parcialmente durante un create() fallido."""
        # Sniffer primero — depende del namespace de red del vulnerable
        if has_sniffer:
            self._destroy_sniffer(env_id)

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
            self._destroy_network(env_id)

        if has_dirs:
            vol_base = self._volume_base(env_id)
            shutil.rmtree(vol_base, ignore_errors=True)

    def destroy(self, env_id: str) -> None:
        self._baselines.pop(env_id, None)
        self._baseline_strategies.pop(env_id, None)
        timeout = self.config.container_stop_timeout

        # Sniffer primero (depende del namespace de red del vulnerable)
        self._destroy_sniffer(env_id)

        # Contenedores
        for role in ("vulnerable", "attacker"):
            name = self._container_name(env_id, role)
            try:
                c = self.client.containers.get(name)
                try:
                    c.stop(timeout=timeout)
                except Exception as exc:
                    logger.warning("No se pudo detener %s, forzando remove: %s", name, exc)
                c.remove(force=True)
            except NotFound:
                pass

        # Redes (interna + externa)
        self._destroy_network(env_id)

        # Volúmenes (directorios)
        vol_base = self._volume_base(env_id)
        if vol_base.exists():
            shutil.rmtree(vol_base)

        # Estado persistido (baseline)
        state = self._state_dir(env_id)
        if state.exists():
            shutil.rmtree(state, ignore_errors=True)

    def attach_existing(self, env_id: str) -> Environment:
        """Reconstruye el estado interno para un entorno ya creado en Docker.

        Útil para que el daemon retome el monitoreo de runs que la CLI
        creó en un proceso distinto. Carga el baseline desde disco si está
        presente; si no, reinicia con baseline vacío (el daemon registrará
        cualquier diff actual como cambio del estudiante).
        """
        vuln_name = self._container_name(env_id, "vulnerable")
        try:
            vuln = self.client.containers.get(vuln_name)
        except NotFound:
            raise EnvironmentNotFoundError(
                f"Contenedor vulnerable '{vuln_name}' no existe en Docker."
            )

        labels = vuln.labels or {}
        scenario_id = labels.get(LABEL_SCENARIO_ID, "")
        participant_id = labels.get(LABEL_PARTICIPANT_ID, "")

        attacker_name: str | None = None
        try:
            self.client.containers.get(self._container_name(env_id, "attacker"))
            attacker_name = self._container_name(env_id, "attacker")
        except NotFound:
            pass

        if not self._load_baseline(env_id):
            self._baselines[env_id] = set()
            self._baseline_strategies[env_id] = "unknown"

        vol_base = self._volume_base(env_id)

        return Environment(
            env_id=env_id,
            scenario_id=scenario_id,
            participant_id=participant_id,
            container_vulnerable_name=vuln_name,
            container_attacker_name=attacker_name,
            network_name=self._network_name(env_id),
            status="running",
            created_at=datetime.now(timezone.utc),
            volume_base_path=str(vol_base),
            volume_mappings={},
            baseline_strategy=self._baseline_strategies.get(env_id, "unknown"),
        )

    def reset(self, env_id: str) -> None:
        self._baselines.pop(env_id, None)
        self._baseline_strategies.pop(env_id, None)
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

        # ¿Había sniffer? ¿con qué filtro? — para recrearlo idéntico
        had_sniffer = False
        capture_filter = ""
        try:
            old_sniffer = self.client.containers.get(
                self._container_name(env_id, "sniffer")
            )
            had_sniffer = True
            capture_filter = (old_sniffer.labels or {}).get(LABEL_CAPTURE_FILTER, "")
        except NotFound:
            pass

        timeout = self.config.container_stop_timeout

        # Sniffer primero: comparte el netns del vulnerable que vamos a borrar
        self._destroy_sniffer(env_id)

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
        internal_net_name = self._network_name(env_id)
        external_net_name = self._external_network_name(env_id)

        # Recrear contenedor vulnerable (sin bind mounts)
        try:
            self.client.containers.run(
                image,
                name=self._container_name(env_id, "vulnerable"),
                network=internal_net_name,
                labels=all_labels,
                detach=True,
                stdin_open=True,
                stop_signal="SIGTERM",
            )
        except APIError as exc:
            raise ContainerStartError(
                f"Error al reiniciar contenedor vulnerable: {exc}"
            )

        # Recrear contenedor atacante si existía — interno + externo
        if attacker_image is not None:
            attacker_name = self._container_name(env_id, "attacker")
            try:
                self.client.containers.run(
                    attacker_image,
                    name=attacker_name,
                    network=internal_net_name,
                    labels=all_labels,
                    detach=True,
                    stdin_open=True,
                    stop_signal="SIGTERM",
                )
                ext_net = self.client.networks.get(external_net_name)
                ext_net.connect(attacker_name)
            except APIError as exc:
                raise ContainerStartError(
                    f"Error al reiniciar contenedor atacante: {exc}"
                )

        # Recrear el sniffer si el entorno tenía captura de red
        if had_sniffer:
            # Dar un instante a que el vulnerable arranque antes de unir su netns
            time.sleep(1.0)
            self._create_sniffer(env_id, capture_filter=capture_filter)


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
            baseline_strategy=self._baseline_strategies.get(env_id, "unknown"),
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
            # Race con destroy/reset: el contenedor existe pero ya no corre.
            # Tratarlo como "entorno desaparecido" para que el monitor pare
            # limpiamente sin traceback ruidoso.
            if "is not running" in str(exc).lower():
                raise EnvironmentNotFoundError(
                    f"Contenedor '{c.name}' detenido durante diff (env_id={env_id})."
                ) from exc
            raise ProviderError(f"Error obteniendo diff del filesystem: {exc}")
        if diff is None:
            return []
        baseline = self._baselines.get(env_id, set())
        return [
            {"kind": item["Kind"], "path": item["Path"]}
            for item in diff
            if item["Path"] not in baseline
        ]

    def get_processes(self, env_id: str) -> list[ProcessInfo]:
        c = self._get_container(env_id, "vulnerable")
        try:
            # Primera llamada: sólo PID + lstart.
            # ps devuelve lstart como 5 tokens separados por espacios
            # (DiaSemana Mes Dia HH:MM:SS Año), que Docker divide en tokens
            # individuales al hacer split por whitespace. Usar dos llamadas
            # separadas evita el overflow de columnas que ocurre con una sola
            # llamada que mezcle lstart con euid/ppid/cmd.
            top_lstart = c.top(ps_args="-o pid,lstart")
            # Segunda llamada: PID + euid + ppid + cmd (cmd absorbe el resto)
            top_info = c.top(ps_args="-o pid,euid,ppid,cmd")
        except APIError as exc:
            # Race con destroy/reset: idem get_filesystem_diff.
            if "is not running" in str(exc).lower():
                raise EnvironmentNotFoundError(
                    f"Contenedor '{c.name}' detenido durante top (env_id={env_id})."
                ) from exc
            raise ProviderError(f"Error obteniendo procesos: {exc}")

        # Parsear lstart: cada fila = [pid, DiaSem, Mes, Dia, HH:MM:SS, Año]
        lstart_by_pid: dict[str, str] = {}
        for row in top_lstart.get("Processes", []):
            if len(row) >= 6:
                pid = row[0].strip()
                lstart = " ".join(row[1:6]).strip()
                lstart_by_pid[pid] = lstart

        # Parsear info: cada fila = [pid, euid, ppid, ...tokens cmd...]
        processes_by_pid: dict[str, ProcessInfo] = {}
        for row in top_info.get("Processes", []):
            if len(row) < 4:
                continue
            pid = row[0].strip()
            try:
                euid = int(row[1].strip())
            except ValueError:
                continue
            ppid = row[2].strip()
            cmd = " ".join(row[3:]).strip()
            lstart = lstart_by_pid.get(pid, "")
            process_id = (
                make_process_id(pid, lstart) if lstart else make_process_id(pid, cmd)
            )
            processes_by_pid[pid] = ProcessInfo(
                pid=pid,
                euid=euid,
                ppid=ppid,
                cmd=cmd,
                lstart=lstart,
                process_id=process_id,
                ppid_cmd="",
                ancestor_cmds=[],
            )

        # Resolver ppid_cmd y ancestor_cmds cruzando por PID
        for info in processes_by_pid.values():
            parent = processes_by_pid.get(info.ppid)
            info.ppid_cmd = parent.cmd if parent else ""
            info.ancestor_cmds = _resolve_ancestors(info.pid, processes_by_pid)

        return list(processes_by_pid.values())

    def cleanup_all(self) -> None:
        """Elimina TODOS los recursos de FlexiPwn (emergencia)."""
        # Contenedores
        containers = self.client.containers.list(
            all=True, filters={"label": f"{LABEL_MANAGED}=true"}
        )
        # Sniffers primero: comparten el netns del vulnerable; borrarlos
        # después dejaría el netns colgando y remove con EPERM.
        ordered = sorted(
            containers,
            key=lambda c: 0 if c.name.endswith("-sniffer") else 1,
        )
        for c in ordered:
            try:
                c.remove(force=True)
            except Exception as exc:
                logger.warning(
                    "cleanup_all: error eliminando contenedor %s: %s", c.name, exc
                )

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
