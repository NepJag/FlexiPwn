from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from flexipwn.layer4.db import repository
from flexipwn.layer4.db.session import get_session
from flexipwn.layer3.schema import load_scenario

app = typer.Typer(help="Gestión de escenarios")
console = Console()


@app.command("load")
def scenario_load(yaml_path: str = typer.Argument(..., help="Ruta al archivo YAML del escenario")) -> None:
    """Carga y persiste un escenario desde un archivo YAML."""
    path = Path(yaml_path)
    if not path.exists():
        console.print(f"[red]Archivo no encontrado:[/red] {yaml_path}")
        raise typer.Exit(1)
    try:
        with get_session() as session:
            scenario = repository.create_scenario(session, str(path))
    except ValueError as exc:
        console.print(f"[red]Error de validación:[/red] {exc}")
        raise typer.Exit(1)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    console.print(Panel(
        f"[bold green]Escenario cargado[/bold green]\n\n"
        f"[dim]ID:[/dim]       [cyan]{scenario.id}[/cyan]\n"
        f"[dim]Título:[/dim]   {scenario.title}\n"
        f"[dim]Nivel:[/dim]    {scenario.level}\n"
        f"[dim]Categoría:[/dim] {scenario.category}\n"
        f"[dim]Imagen:[/dim]   {scenario.image}",
        border_style="green",
    ))


@app.command("list")
def scenario_list() -> None:
    """Lista todos los escenarios persistidos."""
    with get_session() as session:
        scenarios = repository.list_scenarios(session)

    if not scenarios:
        console.print("[dim]No hay escenarios cargados. Usa 'flexipwn scenario load <yaml>'.[/dim]")
        return

    table = Table(title="Escenarios", show_header=True)
    # overflow="fold" envuelve el UUID (36 chars) en varias líneas cuando la
    # tabla no cabe, en vez de recortarlo con "…" (overflow ellipsis por defecto).
    table.add_column("ID", style="dim", width=36, overflow="fold")
    table.add_column("Título")
    table.add_column("Nivel", style="cyan")
    table.add_column("Categoría")
    table.add_column("Imagen")
    for s in scenarios:
        table.add_row(str(s.id), s.title, s.level, s.category, s.image)
    console.print(table)


@app.command("show")
def scenario_show(scenario_id: str = typer.Argument(..., help="UUID del escenario")) -> None:
    """Muestra los detalles completos de un escenario."""
    with get_session() as session:
        scenario = repository.get_scenario(session, scenario_id)

    if scenario is None:
        console.print(f"[red]Escenario no encontrado:[/red] {scenario_id}")
        raise typer.Exit(1)

    try:
        config = repository.parse_scenario_config(scenario)
    except Exception as exc:
        console.print(f"[red]Error parseando yaml_content:[/red] {exc}")
        raise typer.Exit(1)

    console.print(Panel(
        f"[bold cyan]{scenario.title}[/bold cyan]\n\n"
        f"{scenario.description}\n\n"
        f"[dim]Autor:[/dim]    {scenario.author}\n"
        f"[dim]Nivel:[/dim]    {scenario.level}\n"
        f"[dim]Categoría:[/dim] {scenario.category}\n"
        f"[dim]Imagen:[/dim]   {scenario.image}\n"
        f"[dim]Attacker:[/dim] {scenario.attacker_image or '—'}\n"
        f"[dim]Timeout:[/dim]  {scenario.timeout_seconds}s\n"
        f"[dim]Condición:[/dim] {config.condition.upper()}",
        title=f"Escenario {scenario.id}",
        border_style="cyan",
    ))

    table = Table(title="Targets", show_header=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Tipo", style="cyan")
    table.add_column("Descripción")
    for i, t in enumerate(config.targets, 1):
        table.add_row(str(i), t.type, t.description)
    console.print(table)

    if config.hints:
        console.print("\n[bold]Pistas:[/bold]")
        for h in config.hints:
            console.print(f"  [dim]•[/dim] {h}")


@app.command("validate")
def scenario_validate(yaml_path: str = typer.Argument(..., help="Ruta al archivo YAML")) -> None:
    """Valida un archivo YAML de escenario sin persistirlo."""
    path = Path(yaml_path)
    if not path.exists():
        console.print(f"[red]Archivo no encontrado:[/red] {yaml_path}")
        raise typer.Exit(1)
    try:
        config = load_scenario(path)
    except (ValueError, Exception) as exc:
        console.print(f"[red]Validación fallida:[/red] {exc}")
        raise typer.Exit(1)
    console.print(
        f"[green]✓ YAML válido[/green] — {config.title!r} "
        f"({len(config.targets)} targets, condición: {config.condition})"
    )
