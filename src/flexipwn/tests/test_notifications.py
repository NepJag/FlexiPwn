from __future__ import annotations

from io import StringIO

from rich.console import Console

from flexipwn.layer4.core.notifications import (
    Notification,
    NotificationKind,
    NotificationPolicy,
    NotificationSink,
)


def _sink_with_buffer() -> tuple[NotificationSink, StringIO]:
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=120, no_color=True)
    return NotificationSink(console), buf


def test_ssh_ready_se_silencia_pero_queda_en_buffer():
    sink, buf = _sink_with_buffer()
    sink.emit(
        Notification(
            kind=NotificationKind.SSH_READY,
            env_id="run-aaaa1111",
            message="SSH listo: ssh u@h -p 2200 (clave: secreta)",
        )
    )
    # No se imprime al TTY...
    assert buf.getvalue() == ""
    # ...pero sí queda en el buffer (base del feed).
    recientes = sink.recent()
    assert len(recientes) == 1
    assert recientes[0].kind is NotificationKind.SSH_READY


def test_progreso_se_silencia_por_defecto():
    # Cambio de diseño: el feed/dashboard reemplaza los prints intercalados,
    # así que PROGRESS y TARGET_MATCHED se silencian por defecto. El equivalente
    # persistente vive en ExerciseRun.progress / TargetResult.matched_at.
    sink, buf = _sink_with_buffer()
    sink.emit(
        Notification(
            kind=NotificationKind.PROGRESS,
            env_id="run-bbbb2222",
            message="[run-bbbb2222] Progreso: 1/3 (33%)",
        )
    )
    assert buf.getvalue() == ""
    assert len(sink.recent()) == 1


def test_set_policy_print_reactiva_progreso_en_caliente():
    # set_policy(PRINT) sigue permitiendo volver al modo ruidoso (base de un
    # futuro `notify level`/`--verbose`).
    sink, buf = _sink_with_buffer()
    sink.set_policy(NotificationKind.PROGRESS, NotificationPolicy.PRINT)
    sink.emit(
        Notification(
            kind=NotificationKind.PROGRESS,
            env_id="run-bbbb2222",
            message="[run-bbbb2222] Progreso: 1/3 (33%)",
        )
    )
    assert "Progreso: 1/3 (33%)" in buf.getvalue()


def test_set_policy_silencia_progreso_en_caliente():
    sink, buf = _sink_with_buffer()
    sink.set_policy(NotificationKind.PROGRESS, NotificationPolicy.SILENCE)
    sink.emit(
        Notification(
            kind=NotificationKind.PROGRESS,
            env_id="run-cccc3333",
            message="[run-cccc3333] Progreso: 2/3 (66%)",
        )
    )
    assert buf.getvalue() == ""
    assert len(sink.recent()) == 1


def test_recent_respeta_limite():
    sink, _ = _sink_with_buffer()
    for i in range(5):
        sink.emit(
            Notification(
                kind=NotificationKind.TARGET_MATCHED,
                env_id="run-dddd4444",
                message=f"objetivo {i}",
            )
        )
    assert len(sink.recent(limit=2)) == 2
    assert len(sink.recent()) == 5
