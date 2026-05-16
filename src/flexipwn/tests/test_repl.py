"""Tests del FlexiPwnREPL — dispatch sin Docker, sin prompt_toolkit interactivo."""
from __future__ import annotations

import os
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock

from rich.console import Console

from flexipwn.layer4.core.repl import FlexiPwnREPL


def _make_repl(loop=None) -> tuple[FlexiPwnREPL, StringIO]:
    """REPL aislado: console a StringIO, history a /dev/null, loop mock."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, no_color=True, width=120)
    repl = FlexiPwnREPL(
        loop=loop or MagicMock(),
        console=console,
        history_path=Path(os.devnull),
        stop_loop_on_exit=True,
        prompter=lambda text: "1",  # respuesta determinista para wizards
    )
    return repl, buf


def test_repl_dispatches_known_command():
    """dispatch_line invoca el handler registrado y respeta longitud de prefijo."""
    repl, _ = _make_repl()
    called: list[list[str]] = []
    repl.handlers["scenario list"] = lambda args: called.append(args)
    # Reordena dispatch por longitud (el constructor ya lo hizo, pero el reemplazo
    # del handler conserva la clave).
    repl._dispatch_order = sorted(repl.handlers, key=len, reverse=True)

    repl.dispatch_line("scenario list")
    assert called == [[]]


def test_repl_passes_args_to_handler():
    repl, _ = _make_repl()
    received: list[list[str]] = []
    repl.handlers["scenario load"] = lambda args: received.append(args)
    repl._dispatch_order = sorted(repl.handlers, key=len, reverse=True)

    repl.dispatch_line("scenario load /tmp/x.yaml")
    assert received == [["/tmp/x.yaml"]]


def test_repl_unknown_command_shows_help_hint():
    repl, buf = _make_repl()
    repl.dispatch_line("foobar baz")
    out = buf.getvalue()
    assert "desconocido" in out.lower()
    assert "help" in out.lower()


def test_repl_help_lists_commands():
    repl, buf = _make_repl()
    repl.dispatch_line("help")
    out = buf.getvalue()
    for expected in ("scenario list", "run start", "daemon status", "exit"):
        assert expected in out


def test_repl_exit_stops_loop_when_configured():
    """En foreground (stop_loop_on_exit=True), cerrar el REPL llama loop.stop()."""
    loop = MagicMock()
    repl, _ = _make_repl(loop=loop)
    # Simula el final del bucle prompt: prompt EOFError.
    repl.session = MagicMock()
    repl.session.prompt.side_effect = EOFError()
    repl.run()
    loop.stop.assert_called_once()


def test_repl_exit_does_not_stop_loop_in_attach_mode():
    loop = MagicMock()
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, no_color=True, width=120)
    repl = FlexiPwnREPL(
        loop=loop,
        console=console,
        history_path=Path(os.devnull),
        stop_loop_on_exit=False,
        prompter=lambda text: "",
    )
    repl.session = MagicMock()
    repl.session.prompt.side_effect = EOFError()
    repl.run()
    loop.stop.assert_not_called()


def test_repl_exception_in_handler_does_not_kill_loop():
    repl, buf = _make_repl()

    def boom(args: list[str]) -> None:
        raise RuntimeError("simulated")

    repl.handlers["scenario list"] = boom
    repl._dispatch_order = sorted(repl.handlers, key=len, reverse=True)
    repl.dispatch_line("scenario list")
    out = buf.getvalue()
    assert "simulated" in out.lower()
