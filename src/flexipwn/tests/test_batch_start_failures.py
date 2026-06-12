from __future__ import annotations

import uuid
from io import StringIO
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from flexipwn.layer4.cli import run as run_mod
from flexipwn.layer4.cli.run import ProvisionError, run_batch_start


def _session_cm():
    """Context manager mock cuyo session.get devuelve un run con clave SSH
    ya publicada (para que la espera de credenciales no bloquee el test)."""
    session = MagicMock()
    session.get.return_value = SimpleNamespace(attacker_ssh_password="secret")
    cm = MagicMock()
    cm.__enter__.return_value = session
    cm.__exit__.return_value = False
    return cm


def test_batch_continua_y_reporta_cuando_falla_un_entorno(tmp_path):
    yaml_path = tmp_path / "batch.yaml"
    yaml_path.write_text("assignments:\n  - scenario: S\n    count: 2\n")

    scenario = SimpleNamespace(title="S", id=uuid.uuid4(), attacker_image="img")
    participants = [
        (SimpleNamespace(id=uuid.uuid4(), username="student-ok"), "pw1"),
        (SimpleNamespace(id=uuid.uuid4(), username="student-bad"), "pw2"),
    ]

    repo = MagicMock()
    repo.list_scenarios.return_value = [scenario]
    repo.create_participant.side_effect = participants
    repo.delete_participant = MagicMock()

    buf = StringIO()
    fake_console = Console(file=buf, force_terminal=False, width=200, no_color=True)

    # El primer entorno se aprovisiona bien; el segundo falla.
    provision = MagicMock(
        side_effect=[
            ("run-ok", 2200, uuid.uuid4()),
            ProvisionError("[red]Error creando entorno:[/red] pools agotados"),
        ]
    )

    with patch.object(run_mod, "require_daemon"), \
         patch.object(run_mod, "FlexiPwnConfig"), \
         patch.object(run_mod, "repository", repo), \
         patch.object(run_mod, "get_session", side_effect=lambda: _session_cm()), \
         patch.object(run_mod, "_provision_environment", provision), \
         patch.object(run_mod, "console", fake_console):
        run_batch_start(str(yaml_path), output=None)

    output = buf.getvalue()

    # Se intentaron los dos entornos (no se abortó tras el fallo).
    assert provision.call_count == 2
    # El participante huérfano del entorno fallido se limpió, una sola vez.
    assert repo.delete_participant.call_count == 1
    # Reporte: éxito, fallo y resumen.
    assert "Asignaciones creadas" in output
    assert "Fallos" in output
    assert "pools agotados" in output
    assert "1 creado(s)" in output
    assert "1 fallido(s)" in output


def test_batch_csv_incluye_estado_y_motivo(tmp_path):
    yaml_path = tmp_path / "batch.yaml"
    yaml_path.write_text("assignments:\n  - scenario: S\n    count: 2\n")
    csv_path = tmp_path / "out.csv"

    scenario = SimpleNamespace(title="S", id=uuid.uuid4(), attacker_image="img")
    participants = [
        (SimpleNamespace(id=uuid.uuid4(), username="student-ok"), "pw1"),
        (SimpleNamespace(id=uuid.uuid4(), username="student-bad"), "pw2"),
    ]

    repo = MagicMock()
    repo.list_scenarios.return_value = [scenario]
    repo.create_participant.side_effect = participants
    repo.delete_participant = MagicMock()

    buf = StringIO()
    fake_console = Console(file=buf, force_terminal=False, width=200, no_color=True)
    provision = MagicMock(
        side_effect=[
            ("run-ok", 2200, uuid.uuid4()),
            ProvisionError("[red]boom[/red]"),
        ]
    )

    with patch.object(run_mod, "require_daemon"), \
         patch.object(run_mod, "FlexiPwnConfig"), \
         patch.object(run_mod, "repository", repo), \
         patch.object(run_mod, "get_session", side_effect=lambda: _session_cm()), \
         patch.object(run_mod, "_provision_environment", provision), \
         patch.object(run_mod, "console", fake_console):
        run_batch_start(str(yaml_path), output=str(csv_path))

    content = csv_path.read_text()
    assert "status,error" in content
    assert "created" in content
    assert "failed" in content
    # El markup Rich del motivo se guarda en texto plano.
    assert "boom" in content
    assert "[red]" not in content
