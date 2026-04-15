from dataclasses import dataclass


@dataclass
class FlexiPwnConfig:
    volumes_base_path: str = "/tmp/flexipwn-volumes"
    docker_socket: str | None = None  # None = autodetectar
    container_stop_timeout: int = 10  # segundos antes de SIGKILL
    startup_delay_seconds: float = 3.0  # fallback cuando no hay HEALTHCHECK
    healthcheck_timeout: float = 60.0  # máximo a esperar por "healthy"
    healthcheck_poll_interval: float = 1.0
