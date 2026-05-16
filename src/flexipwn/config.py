import os
from dataclasses import dataclass, field


def _default_host() -> str:
    return os.environ.get("FLEXIPWN_HOST", "localhost")


@dataclass
class FlexiPwnConfig:
    volumes_base_path: str = "/tmp/flexipwn-volumes"
    docker_socket: str | None = None  # None = autodetectar
    container_stop_timeout: int = 10  # segundos antes de SIGKILL
    startup_delay_seconds: float = 3.0  # fallback cuando no hay HEALTHCHECK
    healthcheck_timeout: float = 60.0  # máximo a esperar por "healthy"
    healthcheck_poll_interval: float = 1.0
    db_path: str | None = None  # None → ~/.flexipwn/flexipwn.db o FLEXIPWN_DB_PATH
    super_monitor_max_workers: int = 16
    super_monitor_poll_interval: float = 2.0
    host: str = field(default_factory=_default_host)
    attacker_port_range_start: int = 2200
    attacker_port_range_end: int = 2299
