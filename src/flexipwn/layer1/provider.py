import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime


# ---------------------------------------------------------------------------
# Excepciones
# ---------------------------------------------------------------------------


class ProviderError(Exception): #
    """Error base de proveedores de entorno."""


class SocketNotFoundError(ProviderError):
    """No se encontró un socket Docker válido."""


class ImageNotFoundError(ProviderError): #
    """La imagen Docker solicitada no existe localmente ni en el registro."""


class ContainerStartError(ProviderError):
    """El contenedor no pudo arrancar."""


class EnvironmentNotFoundError(ProviderError): #
    """El entorno solicitado no existe o ya fue destruido."""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class Environment:
    env_id: str
    scenario_id: str
    participant_id: str
    container_vulnerable_name: str
    container_attacker_name: str | None
    network_name: str
    status: str  # "running" | "stopped" | "destroyed"
    created_at: datetime
    volume_base_path: str  # path en el host
    volume_mappings: dict[str, str]  # container_path -> host_path
    baseline_strategy: str  # "healthcheck" | "delay" | "timeout" | "unknown"


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str


@dataclass
class ProcessInfo:
    pid: str
    euid: int
    ppid: str
    cmd: str
    lstart: str       # tiempo de inicio: "Mon Oct 23 10:25:44 2023"
    process_id: str   # sha256[:12] de "{pid}:{lstart}" — identifica unívocamente
                      # el proceso aunque el PID se reutilice


def make_process_id(pid: str, disambiguator: str) -> str:
    """Hash sha256[:12] de '{pid}:{disambiguator}'.

    disambiguator es cualquier string que distinga al proceso aunque su PID se reutilice.
    En la práctica se usa 'ppid:cmd' ya que container.top() no expone lstart sin overflow.
    """
    raw = f"{pid}:{disambiguator}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# ABC
# ---------------------------------------------------------------------------


class EnvironmentProvider(ABC):

    @abstractmethod
    def create(
        self,
        scenario_id: str,
        participant_id: str,
        image: str,
        attacker_image: str | None = None,
        ports: list[str] | None = None,
        timeout_seconds: int = 1800,
        startup_delay: float | None = None,
    ) -> Environment:
        """Crea y levanta el entorno completo (red + contenedores + volúmenes)."""
        ...

    @abstractmethod
    def destroy(self, env_id: str) -> None:
        """Detiene y elimina contenedores, red y directorios de volúmenes."""
        ...

    @abstractmethod
    def reset(self, env_id: str) -> None:
        """Recrea los contenedores desde imagen original. Preserva env_id."""
        ...

    @abstractmethod
    def get_status(self, env_id: str) -> Environment:
        ...

    @abstractmethod
    def exec_run(
        self,
        env_id: str,
        cmd: str,
        user: str = "root",
        container: str = "vulnerable",  # "vulnerable" | "attacker"
    ) -> ExecResult:
        """Ejecuta un comando dentro del contenedor. SOLO para monitoreo interno."""
        ...

    @abstractmethod
    def get_filesystem_diff(self, env_id: str) -> list[dict]:
        """
        Retorna los cambios en el filesystem del contenedor respecto a su imagen.
        Usa container.diff() — completamente externo, sin exec, sin bind mounts.

        Retorna lista de dicts: [{"kind": int, "path": str}, ...]
        kind: 0 = modificado, 1 = creado, 2 = eliminado

        Esta función es consumida por el Monitor de filesystem de Capa 2.
        """
        ...

    @abstractmethod
    def get_processes(self, env_id: str) -> list[ProcessInfo]:
        """
        Retorna procesos activos del contenedor vulnerable.
        DEBE usar container.top() o lectura de /proc en el host.
        NUNCA usar exec_run("ps ...") — viola el principio de pasividad.
        """
        ...

    @abstractmethod
    def cleanup_all(self) -> None:
        """Elimina TODOS los recursos de FlexiPwn en el sistema (emergencia)."""
        ...
