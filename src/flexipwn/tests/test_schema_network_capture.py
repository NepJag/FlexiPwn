"""
Tests del gate de captura de red derivado del árbol de targets.

Regresión: `enable_network_capture` se calculaba inspeccionando solo los
targets de primer nivel (`any(t.type.startswith("network_") for t in
scenario.targets)`). Cuando una hoja network_* quedaba envuelta en un nodo
lógico (and/or/not), el gate daba False, el NetworkMonitor no se levantaba y
la conexión (p. ej. la reverse shell) nunca se detectaba.

`iter_leaf_targets` + `scenario_requires_network_capture` recorren el árbol
completo y arreglan el caso.
"""

from pathlib import Path

import pytest

from flexipwn.layer3.schema import (
    EnvironmentConfig,
    ScenarioConfig,
    TargetConfig,
    iter_leaf_targets,
    load_scenario,
    scenario_requires_network_capture,
)

_ENV = EnvironmentConfig(image="debian:12")


def _scenario(targets: list[TargetConfig], condition: str = "all") -> ScenarioConfig:
    return ScenarioConfig(
        title="t",
        description="d",
        author="a",
        level="intermediate",
        category="web",
        environment=_ENV,
        targets=targets,
        condition=condition,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# iter_leaf_targets
# ---------------------------------------------------------------------------


def test_iter_leaf_targets_flat() -> None:
    targets = [
        TargetConfig(type="network_connection", dst_port=4444, description="x"),
        TargetConfig(type="file_created", path="/root/", description="y"),
    ]
    leaves = list(iter_leaf_targets(targets))
    assert [t.type for t in leaves] == ["network_connection", "file_created"]


def test_iter_leaf_targets_recurses_into_logical_nodes() -> None:
    targets = [
        TargetConfig(
            type="and",
            description="and",
            targets=[
                TargetConfig(
                    type="or",
                    description="or",
                    targets=[
                        TargetConfig(type="network_connection", dst_port=4444, description="a"),
                        TargetConfig(type="network_connection", dst_port=9001, description="b"),
                    ],
                ),
                TargetConfig(type="file_created", path="/root/", description="c"),
            ],
        )
    ]
    leaf_types = [t.type for t in iter_leaf_targets(targets)]
    # Los nodos lógicos NO se emiten; sí las 3 hojas, en orden de recorrido.
    assert leaf_types == ["network_connection", "network_connection", "file_created"]


# ---------------------------------------------------------------------------
# scenario_requires_network_capture
# ---------------------------------------------------------------------------


def test_capture_true_when_network_leaf_at_top_level() -> None:
    sc = _scenario([
        TargetConfig(type="network_connection", dst_port=4444, description="x"),
        TargetConfig(type="file_created", path="/root/", description="y"),
    ])
    assert scenario_requires_network_capture(sc) is True


def test_capture_true_when_network_leaf_nested_in_and_or() -> None:
    """El caso del bug: hoja network_* envuelta en and/or."""
    sc = _scenario([
        TargetConfig(
            type="and",
            description="and",
            targets=[
                TargetConfig(
                    type="or",
                    description="or",
                    targets=[
                        TargetConfig(type="network_connection", dst_port=4444, description="a"),
                        TargetConfig(type="network_connection", dst_port=9001, description="b"),
                    ],
                ),
                TargetConfig(type="file_created", path="/root/", description="c"),
            ],
        )
    ])
    assert scenario_requires_network_capture(sc) is True


def test_capture_false_when_no_network_leaf() -> None:
    sc = _scenario([
        TargetConfig(
            type="and",
            description="and",
            targets=[
                TargetConfig(type="file_created", path="/root/", description="a"),
                TargetConfig(type="process_running", euid=0, cmd_contains="bash", description="b"),
            ],
        )
    ])
    assert scenario_requires_network_capture(sc) is False


# ---------------------------------------------------------------------------
# End-to-end contra los YAML reales del repo
# ---------------------------------------------------------------------------

_SCENARIOS_DIR = Path(__file__).resolve().parents[3] / "scenarios"


@pytest.mark.parametrize(
    "filename",
    ["command-injection-demo.yaml", "command-injection-demo-logical.yaml"],
)
def test_real_command_injection_scenarios_enable_capture(filename: str) -> None:
    """Ambas variantes (plana y lógica) deben activar la captura de red."""
    path = _SCENARIOS_DIR / filename
    if not path.exists():
        pytest.skip(f"escenario no encontrado: {path}")
    sc = load_scenario(path)
    assert scenario_requires_network_capture(sc) is True
