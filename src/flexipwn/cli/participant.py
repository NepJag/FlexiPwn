from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from flexipwn.db import repository
from flexipwn.db.session import get_session

app = typer.Typer(help="Gestión de participantes")
console = Console()


@app.command("add")
def participant_add() -> None:
    """Crea un nuevo participante con credenciales generadas automáticamente."""
    with get_session() as session:
        participant, plaintext = repository.create_participant(session)

    console.print(Panel(
        f"[bold green]Participante creado[/bold green]\n\n"
        f"[dim]Username:[/dim]  [cyan]{participant.username}[/cyan]\n"
        f"[dim]Password:[/dim]  [yellow bold]{plaintext}[/yellow bold]\n\n"
        f"[red bold]⚠ Guarda esta contraseña — no se mostrará de nuevo.[/red bold]",
        title="Nuevo participante",
        border_style="green",
    ))


@app.command("list")
def participant_list() -> None:
    """Lista todos los participantes registrados."""
    with get_session() as session:
        participants = repository.list_participants(session)

    if not participants:
        console.print("[dim]No hay participantes. Usa 'flexipwn participant add'.[/dim]")
        return

    table = Table(title="Participantes", show_header=True)
    table.add_column("Username", style="cyan")
    table.add_column("Creado")
    for p in participants:
        table.add_row(p.username, str(p.created_at)[:19])
    console.print(table)


@app.command("reset-password")
def participant_reset_password(
    username: str = typer.Argument(..., help="Username del participante"),
) -> None:
    """Genera una nueva contraseña para el participante."""
    try:
        with get_session() as session:
            plaintext = repository.reset_participant_password(session, username)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    console.print(Panel(
        f"[bold green]Contraseña actualizada[/bold green]\n\n"
        f"[dim]Username:[/dim]  [cyan]{username}[/cyan]\n"
        f"[dim]Password:[/dim]  [yellow bold]{plaintext}[/yellow bold]\n\n"
        f"[red bold]⚠ Guarda esta contraseña — no se mostrará de nuevo.[/red bold]",
        title="Reset de contraseña",
        border_style="yellow",
    ))
