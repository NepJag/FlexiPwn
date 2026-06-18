"""Tests del visor de estado del estudiante (Funcionalidad 2).

`render_student_status` es una función pura → se testea directamente.
`push_student_status` se testea con un provider mock (sin Docker): verifica que
escribe en el atacante vía exec_run (base64) y que nunca propaga errores.
"""
from __future__ import annotations

import base64
import re
from unittest.mock import MagicMock

from flexipwn.layer3.engine import EvaluationResult
from flexipwn.layer3.engine import TargetResult as ETR
from flexipwn.layer3.schema import ScenarioConfig
from flexipwn.layer4.core.student_status import (
    STATUS_PATH,
    push_student_status,
    render_student_status,
)


def _scenario(hints=("pista uno", "pista dos")) -> ScenarioConfig:
    return ScenarioConfig.model_validate(
        {
            "title": "Demo CI",
            "description": "d",
            "author": "a",
            "level": "beginner",
            "category": "web",
            "environment": {"image": "img", "attacker_image": "atk"},
            "hints": list(hints),
            "targets": [
                {
                    "type": "network_connection",
                    "dst_port": 4444,
                    "description": "Conexion 4444",
                },
                {
                    "type": "file_created",
                    "path": "/root/",
                    "description": "Archivo en root",
                },
            ],
            "condition": "all",
        }
    )


def _result(matched_first: bool, matched_second: bool, completed: bool) -> EvaluationResult:
    return EvaluationResult(
        scenario_id="s",
        participant_id="p",
        env_id="e",
        condition="all",
        targets=[
            ETR(
                target_index=0,
                target_type="network_connection",
                description="Conexion 4444",
                matched=matched_first,
            ),
            ETR(
                target_index=1,
                target_type="file_created",
                description="Archivo en root",
                matched=matched_second,
            ),
        ],
        completed=completed,
        progress=(int(matched_first) + int(matched_second)) / 2,
    )


# ---------------------------------------------------------------------------
# render_student_status
# ---------------------------------------------------------------------------


class TestRender:
    def test_initial_all_unmatched_shows_hints(self):
        text = render_student_status(_scenario(), None)
        assert "FlexiPwn — Demo CI" in text
        assert "Objetivos (0/2):" in text
        assert "[ ] Conexion 4444" in text
        assert "[ ] Archivo en root" in text
        assert "[✔]" not in text
        # Pistas re-surgidas para el estudiante (la "feature perdida").
        assert "Pistas:" in text
        assert "1. pista uno" in text
        assert "2. pista dos" in text

    def test_partial_progress_marks_matched(self):
        text = render_student_status(_scenario(), _result(True, False, completed=False))
        assert "Objetivos (1/2):" in text
        assert "[✔] Conexion 4444" in text
        assert "[ ] Archivo en root" in text
        assert "¡Escenario completado!" not in text

    def test_completed_banner(self):
        text = render_student_status(_scenario(), _result(True, True, completed=True))
        assert "Objetivos (2/2):" in text
        assert "¡Escenario completado!" in text

    def test_no_hints_section_when_empty(self):
        text = render_student_status(_scenario(hints=()), None)
        assert "Pistas:" not in text

    def test_descends_logical_nodes(self):
        """El checklist muestra las HOJAS, no los nodos lógicos and/or/not."""
        result = EvaluationResult(
            scenario_id="s",
            participant_id="p",
            env_id="e",
            condition="all",
            targets=[
                ETR(
                    target_index=0,
                    target_type="and",
                    description="nodo-and",
                    matched=False,
                    children=[
                        ETR(target_index=0, target_type="file_created", description="Hoja A", matched=True),
                        ETR(target_index=1, target_type="process_running", description="Hoja B", matched=False),
                    ],
                )
            ],
            completed=False,
            progress=0.5,
        )
        text = render_student_status(_scenario(), result)
        assert "Objetivos (1/2):" in text
        assert "[✔] Hoja A" in text
        assert "[ ] Hoja B" in text
        assert "nodo-and" not in text


# ---------------------------------------------------------------------------
# push_student_status
# ---------------------------------------------------------------------------


class TestPush:
    def test_writes_status_to_attacker_via_exec_run(self):
        provider = MagicMock()
        push_student_status(provider, "run-xyz", _scenario(), None)

        provider.exec_run.assert_called_once()
        call = provider.exec_run.call_args
        assert call.args[0] == "run-xyz"
        assert call.kwargs.get("container") == "attacker"
        cmd = call.args[1]
        assert STATUS_PATH in cmd

        # El contenido viaja en base64 → decodifica al texto renderizado.
        match = re.search(r"echo (\S+) \| base64 -d", cmd)
        assert match is not None
        decoded = base64.b64decode(match.group(1)).decode("utf-8")
        assert "Demo CI" in decoded
        assert "Objetivos (0/2):" in decoded

    def test_swallows_exec_errors(self):
        provider = MagicMock()
        provider.exec_run.side_effect = RuntimeError("contenedor en carrera con destroy")
        # No debe propagar: un fallo de exec no puede tumbar el run.
        push_student_status(provider, "run-xyz", _scenario(), None)

    def test_passes_result_progress_into_render(self):
        provider = MagicMock()
        push_student_status(provider, "run-xyz", _scenario(), _result(True, True, completed=False))
        cmd = provider.exec_run.call_args.args[1]
        decoded = base64.b64decode(
            re.search(r"echo (\S+) \| base64 -d", cmd).group(1)
        ).decode("utf-8")
        assert "Objetivos (2/2):" in decoded
