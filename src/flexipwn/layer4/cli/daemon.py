from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import typer
from rich.console import Console

from flexipwn.layer4.core.daemon_loop import DaemonLoop
from flexipwn.layer4.core.pid_file import (
    is_running,
    read_pid,
    remove_pid_file,
    write_pid,
)
from flexipwn.layer4.db import repository
from flexipwn.layer4.db.session import get_session

app = typer.Typer(help="Daemon supervisor del SuperMonitor (FlexiPwn).")
console = Console()


def _flexipwn_dir() -> Path:
    return Path.home() / ".flexipwn"


def _pid_path() -> Path:
    return _flexipwn_dir() / "daemon.pid"


def _log_path() -> Path:
    return _flexipwn_dir() / "daemon.log"


def daemon_is_running() -> bool:
    pid = read_pid(_pid_path())
    if pid is None:
        return False
    if not is_running(pid):
        # Stale PID file
        remove_pid_file(_pid_path())
        return False
    return True


def require_daemon() -> None:
    """Aborta el comando si el daemon no está corriendo."""
    if not daemon_is_running():
        console.print(
            "[red]El daemon de FlexiPwn no está corriendo.[/red]\n"
            "Inícialo con: [yellow]flexipwn daemon start --detach[/yellow]"
        )
        raise typer.Exit(1)


@app.command("start")
def daemon_start(
    detach: bool = typer.Option(
        False, "--detach", help="Lanza el daemon en background sin REPL."
    ),
    no_repl: bool = typer.Option(
        False,
        "--no-repl",
        hidden=True,
        help="Modo interno usado por --detach: corre el loop sin REPL.",
    ),
) -> None:
    """Arranca el daemon supervisor.

    Por defecto (foreground) abre un REPL interactivo. Con --detach corre en
    background y publica un socket Unix para `flexipwn daemon attach`.
    """
    if daemon_is_running():
        console.print("[yellow]El daemon ya está corriendo.[/yellow]")
        raise typer.Exit(1)

    _flexipwn_dir().mkdir(parents=True, exist_ok=True)

    if detach:
        log_file = _log_path()
        with open(log_file, "ab") as logf:
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "flexipwn.layer4.cli.daemon",
                    "start",
                    "--no-repl",
                ],
                stdout=logf,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        for _ in range(20):
            time.sleep(0.1)
            if daemon_is_running():
                break
        if daemon_is_running():
            console.print(
                f"[green]Daemon arrancado en background.[/green] "
                f"PID: {proc.pid}  Log: {log_file}"
            )
        else:
            console.print(
                "[red]El daemon no respondió tras 2s. Revisa el log:[/red] "
                f"{log_file}"
            )
            raise typer.Exit(1)
        return

    # ---- Modo --no-repl (subproceso interno de --detach) ----
    if no_repl:
        write_pid(_pid_path())
        from flexipwn.layer4.core.daemon_sock import (
            BroadcastFile,
            DaemonSocketServer,
        )

        # La salida del DaemonLoop pasa por BroadcastFile: escribe al log
        # (sys.stdout, redirigido por el padre) Y a cada cliente attached.
        broadcast = BroadcastFile(base=sys.stdout)
        daemon_console = Console(
            file=broadcast,
            force_terminal=True,
            color_system="truecolor",
            width=120,
        )
        loop = DaemonLoop(console=daemon_console)
        loop.install_signal_handlers()
        sock_server = None
        try:
            sock_server = DaemonSocketServer(
                sock_path=_flexipwn_dir() / "daemon.sock",
                loop=loop,
                broadcast=broadcast,
            )
            sock_server.start()
            loop.run()
        finally:
            if sock_server is not None:
                sock_server.stop()
            remove_pid_file(_pid_path())
        return

    # ---- Foreground REPL ----
    write_pid(_pid_path())
    loop = DaemonLoop()
    loop_thread = threading.Thread(
        target=loop.run, daemon=True, name="daemon-loop"
    )
    loop_thread.start()
    try:
        from flexipwn.layer4.core.repl import FlexiPwnREPL

        FlexiPwnREPL(loop=loop, console=console).run()
    finally:
        loop.stop()
        loop_thread.join(timeout=10)
        remove_pid_file(_pid_path())


@app.command("stop")
def daemon_stop() -> None:
    """Detiene el daemon en curso."""
    pid = read_pid(_pid_path())
    if pid is None or not is_running(pid):
        console.print("[yellow]El daemon no está corriendo.[/yellow]")
        remove_pid_file(_pid_path())
        raise typer.Exit(1)
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        remove_pid_file(_pid_path())
        console.print("[yellow]El proceso ya no existía.[/yellow]")
        return

    for _ in range(50):
        time.sleep(0.2)
        if not is_running(pid):
            break

    if is_running(pid):
        console.print(
            f"[red]El daemon (PID {pid}) no respondió al SIGTERM en 10s.[/red]"
        )
        raise typer.Exit(1)

    remove_pid_file(_pid_path())
    console.print(f"[green]Daemon detenido (PID {pid}).[/green]")


@app.command("status")
def daemon_status() -> None:
    """Reporta estado del daemon y cuántos runs activos hay."""
    pid = read_pid(_pid_path())
    if pid is None or not is_running(pid):
        console.print("[red]Daemon: detenido[/red]")
        if pid is not None and not is_running(pid):
            console.print(f"[dim]PID file obsoleto (PID {pid}). Usa daemon stop para limpiarlo.[/dim]")
        raise typer.Exit(1)

    with get_session() as session:
        active = repository.get_runs_needing_action(session)

    console.print(f"[green]Daemon: corriendo[/green] (PID {pid})")
    console.print(f"Runs activos: {len(active)}")
    for r in active:
        console.print(f"  • {r.env_id}  [{r.status}]")


@app.command("logs")
def daemon_logs(
    tail: int = typer.Option(50, "--tail", help="Número de líneas a mostrar."),
) -> None:
    """Muestra las últimas N líneas del log del daemon."""
    log = _log_path()
    if not log.exists():
        console.print("[yellow]No hay log de daemon todavía.[/yellow]")
        return
    try:
        with open(log, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            block = 4096
            data = b""
            while size > 0 and data.count(b"\n") <= tail:
                read = min(block, size)
                size -= read
                f.seek(size)
                data = f.read(read) + data
        lines = data.decode("utf-8", errors="replace").splitlines()[-tail:]
        for line in lines:
            console.print(line)
    except OSError as exc:
        console.print(f"[red]Error leyendo log:[/red] {exc}")
        raise typer.Exit(1)


@app.command("attach")
def daemon_attach() -> None:
    """Conecta al daemon en --detach y abre un REPL contra él."""
    if not daemon_is_running():
        console.print(
            "[red]No hay daemon corriendo.[/red] "
            "Inícialo con [yellow]flexipwn daemon start --detach[/yellow]."
        )
        raise typer.Exit(1)
    sock = _flexipwn_dir() / "daemon.sock"
    if not sock.exists():
        console.print(
            "[red]El daemon corre en foreground (sin socket).[/red] "
            "Usa esa terminal o reinícialo con [yellow]--detach[/yellow]."
        )
        raise typer.Exit(1)
    from flexipwn.layer4.core.daemon_sock import attach_client

    attach_client(sock)


# Soporte para `python -m flexipwn.layer4.cli.daemon start`
if __name__ == "__main__":
    app()
