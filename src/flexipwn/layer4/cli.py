from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from flexipwn.config import FlexiPwnConfig
from flexipwn.layer1.docker_rootless import DockerRootlessProvider
from flexipwn.layer1.provider import ImageNotFoundError
from flexipwn.layer2.filesystem import FilesystemMonitor
from flexipwn.layer3.engine import EvaluationEngine, EvaluationResult
from flexipwn.layer3.schema import load_scenario

app = typer.Typer(help="FlexiPwn — plataforma educativa de ciberseguridad ofensiva")
demo_app = typer.Typer(help="Comandos de demo")
app.add_typer(demo_app, name="demo")

console = Console()

_SCENARIOS_DIR = Path(__file__).parents[3] / "scenarios"


@demo_app.command("privesc")
def demo_privesc() -> None:
    """Lanza el escenario de privilege escalation end-to-end."""
    scenario_path = _SCENARIOS_DIR / "privesc-demo.yaml"
    if not scenario_path.exists():
        console.print(f"[red]Escenario no encontrado:[/red] {scenario_path}")
        raise typer.Exit(1)

    scenario = load_scenario(scenario_path)
    scenario_id = "privesc-demo"
    participant_id = "demo-player"

    # --- Bienvenida ---
    welcome_lines = [f"[bold cyan]{scenario.title}[/bold cyan]", "", scenario.description.strip()]
    if scenario.hints:
        welcome_lines += ["", "[bold]Pistas:[/bold]"]
        for hint in scenario.hints:
            welcome_lines.append(f"  [dim]•[/dim] {hint}")
    console.print(Panel(
        "\n".join(welcome_lines),
        title="FlexiPwn Demo",
        border_style="cyan",
    ))

    flexipwn_config = FlexiPwnConfig()
    effective_delay = (
        scenario.environment.startup_delay_seconds
        if scenario.environment.startup_delay_seconds is not None
        else flexipwn_config.startup_delay_seconds
    )
    console.print(
        f"\n[bold]Iniciando entorno...[/bold] "
        f"[dim](timeout: {scenario.timeout_seconds}s)[/dim]"
    )

    provider = DockerRootlessProvider(config=flexipwn_config)

    # --- Crear entorno con manejo explícito de imagen no encontrada ---
    try:
        env = provider.create(
            scenario_id=scenario_id,
            participant_id=participant_id,
            image=scenario.environment.image,
            attacker_image=scenario.environment.attacker_image,
            ports=scenario.environment.ports or None,
            startup_delay=scenario.environment.startup_delay_seconds,
        )
    except ImageNotFoundError:
        console.print(
            f"\n[red bold]Error:[/red bold] imagen [yellow]{scenario.environment.image!r}[/yellow] "
            f"no encontrada en Docker local."
        )
        console.print(
            f"[dim]Verifica el campo [bold]image[/bold] en {scenario_path.name} "
            f"o descárgala con:[/dim]\n"
            f"  docker pull {scenario.environment.image}"
        )
        raise typer.Exit(1)

    if env.baseline_strategy == "healthcheck":
        console.print("✓ Contenedor healthy — baseline tomado.", style="green")
    elif env.baseline_strategy == "delay":
        console.print(
            f"⚠ Sin HEALTHCHECK detectado — baseline tomado después de "
            f"{effective_delay}s. Para mayor robustez, agrega HEALTHCHECK "
            f"a tu Dockerfile.",
            style="yellow",
        )
    else:  # timeout
        console.print(
            "⚠ HEALTHCHECK configurado pero no respondió a tiempo. "
            "Baseline tomado igualmente. Revisa el Dockerfile.",
            style="yellow",
        )

    start_time = datetime.now(timezone.utc)
    monitor: FilesystemMonitor | None = None

    # --- Inyectar hints del escenario en el .bashrc del contenedor ---
    # Se escribe el bloque como base64 para evitar problemas de escaping con
    # comillas, emojis y caracteres especiales. El contenido decodificado son
    # comandos `echo "..."` que bash ejecutará al iniciar sesión.
    if scenario.hints:
        import base64
        lines = ["", *[f'echo "💡 {h}"' for h in scenario.hints]]
        payload = base64.b64encode("\n".join(lines).encode()).decode()
        provider.exec_run(
            env.env_id,
            f"bash -c 'base64 -d <<< {payload} >> /home/ctfuser/.bashrc'",
        )

    # --- Info de conexión ---
    console.print(f"\n[green]Entorno creado:[/green] [bold]{env.env_id}[/bold]")
    console.print(Panel(
        f"[bold]Conéctate al contenedor vulnerable:[/bold]\n\n"
        f"  [yellow]docker exec -u ctfuser -it {env.container_vulnerable_name} bash[/yellow]\n\n"
        f"[dim]La imagen no tiene SSH — conexión vía docker exec[/dim]",
        title="Conexión",
        border_style="yellow",
    ))

    # --- Tabla de targets ---
    table = Table(title="Objetivos del escenario", show_header=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Tipo", style="cyan")
    table.add_column("Descripción")
    for i, target in enumerate(scenario.targets, 1):
        table.add_row(str(i), target.type, target.description)
    console.print(table)
    console.print(
        f"\n[dim]Condición de éxito:[/dim] [bold]{scenario.condition.upper()}[/bold] "
        f"de los {len(scenario.targets)} objetivos\n"
    )

    # --- Callbacks ---
    _reported: set[int] = set()  # target_index ya impresos

    def handle_update(result: EvaluationResult) -> None:
        nonlocal monitor

        # Imprimir solo los targets recién matcheados (no repetir)
        for t in result.targets:
            if t.matched and t.target_index not in _reported:
                _reported.add(t.target_index)
                path = t.trigger_event.details.get("path", "") if t.trigger_event else ""
                progress_pct = int(result.progress * 100)
                console.print(
                    f"[green]✓[/green] Target [{t.target_index + 1}/{len(result.targets)}] "
                    f"[cyan]{t.target_type}[/cyan]: {t.description}  "
                    f"[dim]{path}[/dim]  → [bold]{progress_pct}%[/bold]"
                )

        if not result.completed:
            return

        elapsed = datetime.now(timezone.utc) - start_time
        matched_targets = [t for t in result.targets if t.matched]
        lines = ["[bold green]Ejercicio completado[/bold green]", ""]
        for t in matched_targets:
            path = t.trigger_event.details.get("path", "") if t.trigger_event else ""
            lines.append(f"  [cyan]{t.target_type}[/cyan]  {path}")
        lines += ["", f"  Tiempo: [bold]{int(elapsed.total_seconds())}s[/bold]"]
        console.print(Panel("\n".join(lines), title="Resultado", border_style="green"))
        if monitor is not None:
            monitor.stop()

    def handle_stopped(env_id: str) -> None:
        console.print(f"\n[yellow]Contenedor detenido:[/yellow] {env_id}")

    def handle_timeout() -> None:
        elapsed = datetime.now(timezone.utc) - start_time
        console.print(
            f"\n[red]Tiempo agotado[/red] ({int(elapsed.total_seconds())}s). "
            f"El ejercicio no fue completado."
        )
        if monitor is not None:
            monitor.stop()

    # --- Engine + Monitor ---
    engine = EvaluationEngine(
        scenario=scenario,
        scenario_id=scenario_id,
        participant_id=participant_id,
        env_id=env.env_id,
        on_update=handle_update,
    )

    monitor = FilesystemMonitor(
        provider=provider,
        env_id=env.env_id,
        scenario_id=scenario_id,
        participant_id=participant_id,
        on_event=engine.process_event,
        on_stopped=handle_stopped,
        on_timeout=handle_timeout,
        timeout_seconds=scenario.timeout_seconds,
    )

    console.print("[bold]Monitoreando...[/bold] [dim](Ctrl+C para detener)[/dim]\n")

    try:
        monitor.run()
    except KeyboardInterrupt:
        pass
    finally:
        console.print("\n[dim]Destruyendo entorno...[/dim]")
        try:
            provider.destroy(env.env_id)
        except Exception as exc:
            console.print(f"[red]Error destruyendo entorno:[/red] {exc}")
        console.print("[green]Listo.[/green]")
