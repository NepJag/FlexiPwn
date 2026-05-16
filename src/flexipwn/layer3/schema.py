from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, model_validator


class TargetConfig(BaseModel):
    type: Literal[
        "file_created",
        "file_modified",
        "file_exists",
        "process_running",
        "log_pattern",
        "http_response_contains",
        "database_query_result",
        # Nodos lógicos — se evalúan recursivamente en el engine
        "and",
        "or",
        "not",
    ]
    description: str
    # Sub-targets para nodos lógicos (recursivo)
    targets: list["TargetConfig"] | None = None
    # Campos de filesystem
    path: str | None = None
    pattern: str | None = None     # glob, solo si path termina en /
    contains: str | None = None    # substring para file_exists
    # Campos de proceso
    euid: int | None = None
    cmd_contains: str | None = None
    ppid_cmd_contains: str | None = None   # filtro adicional: substring en cmd del padre
    ancestor_contains: str | None = None   # filtro adicional: substring en cualquier ancestro
    # Campos de log
    field_matches: dict[str, Any] | None = None
    # Campos HTTP
    url_path: str | None = None
    body_contains: str | None = None
    status_code: int | None = None
    # Campos DB
    table: str | None = None
    result_contains: str | None = None

    @model_validator(mode="after")
    def validate_fields_for_type(self) -> "TargetConfig":
        if self.type in ("file_created", "file_modified", "file_exists"):
            if self.path is None:
                raise ValueError(f"El tipo '{self.type}' requiere el campo 'path'")
        if self.type == "process_running":
            if self.euid is None or self.cmd_contains is None:
                raise ValueError("process_running requiere 'euid' y 'cmd_contains'")
        if self.type == "log_pattern":
            if self.field_matches is None:
                raise ValueError("log_pattern requiere 'field_matches'")
        if self.type in ("and", "or"):
            if not self.targets or len(self.targets) < 2:
                raise ValueError(
                    f"El tipo '{self.type}' requiere al menos 2 sub-targets"
                )
        if self.type == "not":
            if not self.targets or len(self.targets) != 1:
                raise ValueError("El tipo 'not' requiere exactamente 1 sub-target")
        if self.type not in ("and", "or", "not") and self.targets is not None:
            raise ValueError(f"El tipo '{self.type}' no acepta sub-targets")
        return self


# Necesario para la auto-referencia recursiva en Pydantic v2
TargetConfig.model_rebuild()


class EnvironmentConfig(BaseModel):
    image: str
    attacker_image: str | None = None
    log_paths: list[str] = []
    volumes: dict[str, str] = {}
    network: str | None = None
    ports: list[str] = []
    startup_delay_seconds: float | None = None
    # None → usa FlexiPwnConfig.startup_delay_seconds como default.
    # 0.0 es válido: el educador confía 100% en el healthcheck y quiere delay=0.


class ScenarioConfig(BaseModel):
    title: str
    description: str
    author: str
    level: Literal["beginner", "intermediate", "advanced"]
    category: Literal["pwning", "web", "database", "forensics", "reversing"]
    environment: EnvironmentConfig
    hints: list[str] = []
    targets: list[TargetConfig]
    condition: Literal["any", "all"]
    timeout_seconds: int = 1800

    @model_validator(mode="after")
    def validate_scenario_targets(self) -> "ScenarioConfig":
        if len(self.targets) < 1:
            raise ValueError("El escenario debe tener al menos un target")
        for target in self.targets:
            if target.type == "not":
                raise ValueError(
                    "Un nodo 'not' no puede ser target de primer nivel. "
                    "Úsalo dentro de un nodo 'and' o 'or'."
                )
        return self


def load_scenario(yaml_path: str | Path) -> ScenarioConfig:
    """
    Carga y valida un archivo YAML de escenario.
    Lanza ValueError con mensaje claro si el schema es inválido.
    Lanza FileNotFoundError si el archivo no existe.
    """
    path = Path(yaml_path)
    if not path.exists():
        raise FileNotFoundError(f"Archivo de escenario no encontrado: {yaml_path}")
    with open(path) as f:
        raw = yaml.safe_load(f)
    try:
        return ScenarioConfig.model_validate(raw)
    except Exception as exc:
        raise ValueError(f"Error de validación en '{yaml_path}': {exc}")
