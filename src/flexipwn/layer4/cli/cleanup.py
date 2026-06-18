"""Limpieza total del laboratorio compartida por escenarios y participantes.

`scenario reset-all` y `participant reset-all` comparten exactamente el mismo
flujo: solo cambia qué entidad se conserva. Por
eso el comportamiento vive aquí, parametrizado por `mode`, y los dos comandos lo
invocan. La confirmación NO es saltable (acción destructiva): siempre exige
escribir BORRAR; no hay flag `--yes`.

El `console` propio de este módulo se registra en los proxies del REPL
(`repl._install_console_proxies`) para que su salida se enrute al frontend
correcto (terminal foreground o socket attach).
"""
from __future__ import annotations

import time
from typing import Callable

from rich.console import Console

from flexipwn.config import FlexiPwnConfig
from flexipwn.layer1.docker_rootless import DockerRootlessProvider
from flexipwn.layer4.db import repository
from flexipwn.layer4.db.session import get_session

console = Console()

# Tiempo máximo que reset-all espera a que el daemon baje los entornos activos
# antes del barrido final idempotente.
RESET_ALL_WAIT_TIMEOUT = 90.0


def _perform_reset_all(
    confirm: Callable[[str], bool], *, mode: str = "scenario"
) -> bool:
    """Reset total del laboratorio, mediado por el daemon (1.B/1.C).

    ``mode="scenario"``  → borra runs + escenarios, conserva participantes.
    ``mode="participant"`` → borra runs + participantes, conserva escenarios.

    Ambos marcan los runs activos como 'stopping' para que el daemon los baje
    sin carreras, luego un barrido final idempotente (`cleanup_all`) y el wipe en
    DB. ``confirm`` se inyecta (typer en la CLI / prompter en el REPL) y SIEMPRE
    se evalúa: la acción no se puede saltar con un flag. Devuelve True si se
    ejecutó el reset.
    """
    from flexipwn.layer4.cli.daemon import require_daemon

    require_daemon()

    with get_session() as session:
        runs = repository.list_runs(session)
        non_terminal = [
            (r.id, r.env_id)
            for r in runs
            if r.status not in repository.TERMINAL_STATUSES
        ]
        total_runs = len(runs)
        if mode == "participant":
            other_count = len(repository.list_participants(session))
            other_label = "participante(s)"
            keep_label = "escenarios"
        else:
            other_count = len(repository.list_scenarios(session))
            other_label = "escenario(s)"
            keep_label = "participantes"

    if total_runs == 0 and other_count == 0:
        console.print("[dim]No hay nada que limpiar.[/dim]")
        return False

    console.print(
        f"[red bold]Reset total del laboratorio.[/red bold] Esto destruirá "
        f"[bold]{len(non_terminal)}[/bold] entorno(s) activo(s), "
        f"[bold]{total_runs}[/bold] run(s) y [bold]{other_count}[/bold] "
        f"{other_label}. Se conservan los {keep_label}. "
        f"[red]Es irreversible.[/red]"
    )
    if not confirm("Confirma el reset total escribiendo BORRAR"):
        console.print("[dim]Cancelado.[/dim]")
        return False

    # 1. Mediación del daemon: marcar los activos como 'stopping'.
    if non_terminal:
        with get_session() as session:
            for run_id, _env_id in non_terminal:
                repository.set_run_status(session, run_id, "stopping")
        console.print(
            f"[cyan]Solicitando al daemon detener {len(non_terminal)} "
            f"entorno(s) activo(s)...[/cyan]"
        )
        # 2. Esperar a que el daemon los lleve a estado terminal.
        deadline = time.monotonic() + RESET_ALL_WAIT_TIMEOUT
        while time.monotonic() < deadline:
            with get_session() as session:
                still = [
                    r
                    for r in repository.list_runs(session)
                    if r.status not in repository.TERMINAL_STATUSES
                ]
            if not still:
                break
            time.sleep(1.0)
        else:
            console.print(
                "[yellow]Algunos entornos no terminaron a tiempo; "
                "el barrido final los limpiará igualmente.[/yellow]"
            )

    # 3. Barrido final idempotente en Docker (residuos / daemon que no alcanzó).
    try:
        DockerRootlessProvider(config=FlexiPwnConfig()).cleanup_all()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]Aviso en cleanup_all:[/yellow] {exc}")

    # 4. Wipe de la DB conservando la entidad correspondiente.
    with get_session() as session:
        if mode == "participant":
            counts = repository.reset_all_keep_scenarios(session)
            removed = (
                f"{counts['runs']} run(s), "
                f"{counts['participants']} participante(s)"
            )
            kept = "Escenarios"
        else:
            counts = repository.reset_all_keep_participants(session)
            removed = (
                f"{counts['runs']} run(s), {counts['scenarios']} escenario(s)"
            )
            kept = "Participantes"

    console.print(
        f"[green]Reset completo.[/green] Eliminados: {removed}. "
        f"{kept} conservados."
    )
    return True
