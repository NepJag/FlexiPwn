from __future__ import annotations

from datetime import datetime, timezone
from io import StringIO

from rich.console import Console

from flexipwn.layer3.engine import EvaluationResult, TargetResult
from flexipwn.layer4.core.notifications import (
    NotificationKind,
    NotificationPolicy,
    NotificationSink,
)
from flexipwn.layer4.core.super_monitor import RichProgressPrinter


def _printing_printer(console: Console) -> RichProgressPrinter:
    """Printer cuyo sink imprime (la política por defecto ahora silencia, así
    que para verificar la salida forzamos PRINT en este test)."""
    sink = NotificationSink(
        console,
        policy={
            NotificationKind.TARGET_MATCHED: NotificationPolicy.PRINT,
            NotificationKind.PROGRESS: NotificationPolicy.PRINT,
        },
    )
    return RichProgressPrinter(notifier=sink)


def _make_result(targets: list[TargetResult], progress: float) -> EvaluationResult:
    return EvaluationResult(
        scenario_id="s",
        participant_id="p",
        env_id="run-aaaa1111",
        condition="all",
        targets=targets,
        completed=False,
        progress=progress,
    )


def test_announces_each_matched_target_once():
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=120, no_color=True)
    printer = _printing_printer(console)
    cb = printer.build_callback("run-aaaa1111")

    t = TargetResult(
        target_index=0,
        target_type="file_created",
        description="Archivo .txt creado",
        matched=True,
        matched_at=datetime.now(timezone.utc),
    )
    cb(_make_result([t], 1.0))
    cb(_make_result([t], 1.0))  # segunda invocación

    output = buf.getvalue()
    # El "✓ Archivo .txt creado" debe aparecer exactamente una vez
    assert output.count("Archivo .txt creado") == 1
    # El progreso aparece cada vez
    assert output.count("Progreso:") == 2


def test_skips_logical_nodes_for_announcement():
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=120, no_color=True)
    printer = _printing_printer(console)
    cb = printer.build_callback("run-bbbb2222")

    leaf = TargetResult(
        target_index=1,
        target_type="file_created",
        description="leaf-target",
        matched=True,
        matched_at=datetime.now(timezone.utc),
    )
    parent = TargetResult(
        target_index=0,
        target_type="and",
        description="and-node",
        matched=True,
        matched_at=datetime.now(timezone.utc),
        children=[leaf],
    )
    cb(_make_result([parent], 1.0))
    output = buf.getvalue()
    assert "leaf-target" in output
    # nodo lógico no se anuncia como hoja
    assert "and-node" not in output
