"""Visor de estado del estudiante en el contenedor atacante (Funcionalidad 2).

El daemon (Capa 4) es el único que conoce a la vez el escenario (título + hints,
desde `ScenarioConfig`) y el progreso de objetivos (desde `EvaluationResult`).
Aquí se renderiza ese estado a texto plano y se escribe en el atacante vía el
contrato existente `EnvironmentProvider.exec_run` (Capa 4 → Capa 1), sin tocar el
contenedor vulnerable: el atacante es el "buzón" del estudiante, su única sesión
que FlexiPwn aprovisiona. El script tonto `flexipwn` de la imagen solo hace `cat`
del archivo, así que no se mezcla lógica entre capas.

Decisiones (ver memoria del proyecto): comando único `flexipwn` (pull), entrega
horneada en la imagen + estado escrito por el daemon, checklist completo con las
descripciones de los objetivos. Anclado al atacante; el vulnerable nunca se toca.
"""
from __future__ import annotations

import base64
import logging
from collections.abc import Iterator
from datetime import datetime

from flexipwn.layer3.engine import EvaluationResult
from flexipwn.layer3.engine import TargetResult as EngineTargetResult
from flexipwn.layer3.schema import ScenarioConfig, iter_leaf_targets

logger = logging.getLogger(__name__)

STATUS_PATH = "/opt/flexipwn/status.txt"
_BAR = "═" * 60


def _iter_result_leaves(
    targets: list[EngineTargetResult],
) -> "Iterator[EngineTargetResult]":
    """Hojas del árbol de resultados del motor en DFS (descendiendo and/or/not).

    Espeja a `schema.iter_leaf_targets` sobre la config: ambos árboles tienen la
    misma forma, así que emiten las hojas en el mismo orden.
    """
    for target in targets:
        if target.children:
            yield from _iter_result_leaves(target.children)
        else:
            yield target


def render_student_status(
    scenario: ScenarioConfig,
    result: EvaluationResult | None = None,
    *,
    now: datetime | None = None,
) -> str:
    """Renderiza el estado del ejercicio (objetivos + pistas + progreso) a texto.

    Función pura. ``result=None`` (recién aprovisionado, aún sin evaluación)
    muestra todos los objetivos sin cumplir. El checklist usa las descripciones
    de las hojas del escenario; las pistas vienen del YAML del escenario.
    """
    if result is None:
        leaves = [(leaf.description, False) for leaf in iter_leaf_targets(scenario.targets)]
        completed = False
    else:
        leaves = [(t.description, t.matched) for t in _iter_result_leaves(result.targets)]
        completed = result.completed

    total = len(leaves)
    matched = sum(1 for _, done in leaves if done)

    lines: list[str] = [
        _BAR,
        f" FlexiPwn — {scenario.title}",
        _BAR,
        "",
        f"Objetivos ({matched}/{total}):",
    ]
    for desc, done in leaves:
        lines.append(f"  {'[✔]' if done else '[ ]'} {desc}")

    if completed:
        lines.append("")
        lines.append("  ✔ ¡Escenario completado!")

    if scenario.hints:
        lines.append("")
        lines.append("Pistas:")
        for i, hint in enumerate(scenario.hints, 1):
            lines.append(f"  {i}. {hint}")

    timestamp = (now or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    lines.append("")
    lines.append(f"(Actualizado {timestamp} · corre 'flexipwn' para refrescar)")
    return "\n".join(lines) + "\n"


def push_student_status(
    provider,
    env_id: str,
    scenario: ScenarioConfig,
    result: EvaluationResult | None = None,
) -> None:
    """Renderiza y escribe el estado en el atacante del entorno ``env_id``.

    Usa `provider.exec_run(..., container="attacker")` (contrato Capa 4 → Capa 1
    ya existente, el mismo que crea el usuario SSH). El texto viaja en base64
    para evitar cualquier problema de comillas/acentos/saltos de línea. Nunca
    propaga errores: un fallo de exec (p. ej. carrera con destroy) se registra y
    se ignora, no debe tumbar el run.
    """
    try:
        text = render_student_status(scenario, result)
        payload = base64.b64encode(text.encode("utf-8")).decode("ascii")
        cmd = (
            "bash -c 'mkdir -p /opt/flexipwn && "
            f"echo {payload} | base64 -d > {STATUS_PATH} && "
            f"chmod 644 {STATUS_PATH}'"
        )
        provider.exec_run(env_id, cmd, container="attacker")
    except Exception:
        logger.exception(
            "No se pudo escribir el estado del estudiante en el atacante (%s)",
            env_id,
        )
