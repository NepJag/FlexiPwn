from __future__ import annotations

import base64
import json
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from flexipwn.config import FlexiPwnConfig
from flexipwn.core.super_monitor import get_super_monitor
from flexipwn.db import repository
from flexipwn.db.models import ExerciseRun, Participant
from flexipwn.db.session import get_session
from flexipwn.layer1.docker_rootless import DockerRootlessProvider
from flexipwn.layer1.provider import Environment, ImageNotFoundError
from flexipwn.layer2.events import MonitorEvent
from flexipwn.layer2.filesystem import FilesystemMonitor
from flexipwn.layer2.log import LogMonitor
from flexipwn.layer2.network import NetworkMonitor
from flexipwn.layer2.orchestrator import MonitorOrchestrator
from flexipwn.layer2.process import ProcessMonitor
from flexipwn.layer3.engine import EvaluationEngine, EvaluationResult
from flexipwn.layer3.schema import ScenarioConfig

app = typer.Typer(help="Gestión de runs")
console = Console()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _build_orchestrator(
    scenario_config: ScenarioConfig,
    docker_env: Environment,
    provider: DockerRootlessProvider,
    event_sink,
    on_stopped,
) -> MonitorOrchestrator:
    """Instancia monitores y devuelve un MonitorOrchestrator listo (sin correr)."""
    enable_network_capture = any(
        t.type.startswith("network_") for t in scenario_config.targets
    )

    host_log_paths = []
    for container_log_path in scenario_config.environment.log_paths:
        relative = container_log_path.lstrip("/")
        host_path = Path(docker_env.volume_base_path) / "logs" / relative
        host_path.parent.mkdir(parents=True, exist_ok=True)
        host_log_paths.append(str(host_path))

    fs_monitor = FilesystemMonitor(
        provider=provider,
        env_id=docker_env.env_id,
        scenario_id=docker_env.scenario_id,
        participant_id=docker_env.participant_id,
        on_event=event_sink,
    )
    proc_monitor = ProcessMonitor(
        provider=provider,
        env_id=docker_env.env_id,
        scenario_id=docker_env.scenario_id,
        participant_id=docker_env.participant_id,
        on_event=event_sink,
    )

    log_monitor = None
    if host_log_paths:
        log_monitor = LogMonitor(
            log_paths=host_log_paths,
            env_id=docker_env.env_id,
            scenario_id=docker_env.scenario_id,
            participant_id=docker_env.participant_id,
            on_event=event_sink,
        )

    network_monitor = None
    if enable_network_capture:
        capture_path = provider.get_capture_host_path(docker_env.env_id)
        if capture_path is not None:
            network_monitor = NetworkMonitor(
                env_id=docker_env.env_id,
                participant_id=docker_env.participant_id,
                scenario_id=docker_env.scenario_id,
                capture_file_path=capture_path,
                on_event=event_sink,
            )

    orchestrator = MonitorOrchestrator(
        fs_monitor,
        proc_monitor,
        log_monitor=log_monitor,
        network_monitor=network_monitor,
        poll_interval=2.0,
    )

    fs_monitor._on_stopped = on_stopped
    proc_monitor._on_stopped = on_stopped

    return orchestrator


def _inject_attacker_password(
    provider: DockerRootlessProvider,
    env_id: str,
    password: str,
    attacker_name: str | None,
) -> None:
    if not attacker_name:
        return
    try:
        provider.exec_run(
            env_id,
            f"bash -c 'echo \"attacker:{password}\" | chpasswd'",
            container="attacker",
        )
    except Exception as exc:
        console.print(f"[yellow]Aviso:[/yellow] no se pudo inyectar contraseña SSH: {exc}")


def _inject_hints(
    provider: DockerRootlessProvider,
    env_id: str,
    hints: list[str],
) -> None:
    if not hints:
        return
    lines = ["", *[f'echo "💡 {h}"' for h in hints]]
    payload = base64.b64encode("\n".join(lines).encode()).decode()
    try:
        provider.exec_run(env_id, f"bash -c 'base64 -d <<< {payload} >> /home/ctfuser/.bashrc'")
    except Exception:
        pass


@app.command("start")
def run_start(
    scenario: str = typer.Option(..., "--scenario", help="UUID del escenario"),
    participant: str = typer.Option(..., "--participant", help="Username del participante"),
    password: str = typer.Option(..., "--password", help="Contraseña del participante"),
) -> None:
    """Inicia un run de ejercicio para un participante en un escenario."""
    flexipwn_config = FlexiPwnConfig()
    provider = DockerRootlessProvider(config=flexipwn_config)

    # Validar participante y credenciales
    with get_session() as session:
        db_participant = repository.get_participant_by_username(session, participant)
        if db_participant is None:
            console.print(f"[red]Participante no encontrado:[/red] {participant!r}")
            raise typer.Exit(1)
        if not repository.verify_participant_password(db_participant, password):
            console.print("[red]Contraseña incorrecta.[/red]")
            raise typer.Exit(1)
        participant_id = db_participant.id

        db_scenario = repository.get_scenario(session, scenario)
        if db_scenario is None:
            console.print(f"[red]Escenario no encontrado:[/red] {scenario!r}")
            raise typer.Exit(1)
        scenario_config = repository.parse_scenario_config(db_scenario)
        scenario_db_id = db_scenario.id

    console.print(
        f"\n[bold]Iniciando entorno...[/bold] "
        f"[dim](timeout: {scenario_config.timeout_seconds}s)[/dim]"
    )

    try:
        docker_env = provider.create(
            scenario_id=str(scenario_db_id),
            participant_id=str(participant_id),
            image=scenario_config.environment.image,
            attacker_image=scenario_config.environment.attacker_image,
            ports=scenario_config.environment.ports or None,
            attacker_ports=scenario_config.environment.attacker_ports or None,
            log_paths=scenario_config.environment.log_paths or None,
            startup_delay=scenario_config.environment.startup_delay_seconds,
            enable_network_capture=any(
                t.type.startswith("network_") for t in scenario_config.targets
            ),
            capture_filter=scenario_config.environment.capture_filter,
        )
    except ImageNotFoundError:
        console.print(
            f"[red bold]Error:[/red bold] imagen "
            f"[yellow]{scenario_config.environment.image!r}[/yellow] "
            f"no encontrada en Docker local."
        )
        raise typer.Exit(1)
    except Exception as exc:
        console.print(f"[red]Error creando entorno:[/red] {exc}")
        raise typer.Exit(1)

    env_id = docker_env.env_id

    _inject_attacker_password(provider, env_id, password, docker_env.container_attacker_name)
    _inject_hints(provider, env_id, scenario_config.hints)

    # Crear registros en DB
    with get_session() as session:
        run = repository.create_run(session, scenario_db_id, participant_id, env_id)
        run_id = run.id
        repository.mark_run_started(session, run_id)
        repository.bulk_create_target_results(session, run_id, scenario_config)

    started_at = _now()
    done_event = threading.Event()
    final_status = {"value": "failed"}
    _reported: set[int] = set()

    def on_update(result: EvaluationResult) -> None:
        with get_session() as s:
            repository.update_run_progress(s, run_id, result.progress)
            repository.update_target_results_from_engine(s, run_id, result)

        for t in result.targets:
            if t.matched and t.target_index not in _reported:
                _reported.add(t.target_index)
                pct = int(result.progress * 100)
                console.print(
                    f"[green]✓[/green] Target [{t.target_index + 1}/{len(result.targets)}] "
                    f"[cyan]{t.target_type}[/cyan]: {t.description} → [bold]{pct}%[/bold]"
                )

        if result.completed:
            final_status["value"] = "completed"
            done_event.set()

    engine = EvaluationEngine(
        scenario=scenario_config,
        scenario_id=str(scenario_db_id),
        participant_id=str(participant_id),
        env_id=env_id,
        on_update=on_update,
    )

    def event_sink(event: MonitorEvent) -> None:
        with get_session() as s:
            repository.append_run_event(s, run_id, event)
        engine.process_event(event)

    orchestrator_holder: list[MonitorOrchestrator] = []

    def on_stopped(stopped_env_id: str) -> None:
        console.print(f"\n[yellow]⚠ Contenedor detenido:[/yellow] {stopped_env_id}")
        if orchestrator_holder:
            orchestrator_holder[0].stop()
        done_event.set()

    def on_timeout(timed_out_env_id: str) -> None:
        console.print(f"\n[red]Tiempo agotado para entorno {timed_out_env_id}[/red]")
        final_status["value"] = "timeout"
        with get_session() as s:
            repository.mark_run_finished(s, run_id, "timeout")
        try:
            provider.destroy(timed_out_env_id)
        except Exception:
            pass
        done_event.set()

    orchestrator = _build_orchestrator(
        scenario_config=scenario_config,
        docker_env=docker_env,
        provider=provider,
        event_sink=event_sink,
        on_stopped=on_stopped,
    )
    orchestrator_holder.append(orchestrator)

    sm = get_super_monitor(
        poll_interval=flexipwn_config.super_monitor_poll_interval,
        max_workers=flexipwn_config.super_monitor_max_workers,
    )
    sm.add_environment(
        env_id=env_id,
        orchestrator=orchestrator,
        run_id=run_id,
        started_at=started_at,
        timeout_seconds=scenario_config.timeout_seconds,
        on_timeout=on_timeout,
    )

    console.print(f"\n[green]Entorno activo:[/green] [bold]{env_id}[/bold]")
    console.print(
        f"[dim]Observa el progreso en otra terminal:[/dim] "
        f"[yellow]flexipwn run watch {env_id}[/yellow]"
    )

    table = Table(title="Objetivos", show_header=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Tipo", style="cyan")
    table.add_column("Descripción")
    for i, t in enumerate(scenario_config.targets, 1):
        table.add_row(str(i), t.type, t.description)
    console.print(table)
    console.print(
        "\n[bold]Monitoreando...[/bold] [dim](Ctrl+C para detener)[/dim]\n"
    )

    try:
        done_event.wait()
    except KeyboardInterrupt:
        pass
    finally:
        sm.remove_environment(env_id)
        orchestrator.stop()
        status = final_status["value"]
        with get_session() as s:
            current = repository.get_run_by_env_id(s, env_id)
            if current and current.status == "running":
                repository.mark_run_finished(s, run_id, status)
        console.print(f"\n[dim]Destruyendo entorno {env_id}...[/dim]")
        try:
            provider.destroy(env_id)
        except Exception as exc:
            console.print(f"[yellow]Aviso destruyendo entorno:[/yellow] {exc}")
        console.print(f"[green]Run {env_id} finalizado ({status}).[/green]")


@app.command("stop")
def run_stop(env_id: str = typer.Argument(..., help="env_id del run")) -> None:
    """Detiene un run activo destruyendo su entorno Docker."""
    with get_session() as session:
        run = repository.get_run_by_env_id(session, env_id)
        if run is None:
            console.print(f"[red]Run no encontrado:[/red] {env_id}")
            raise typer.Exit(1)
        run_id = run.id

    flexipwn_config = FlexiPwnConfig()
    provider = DockerRootlessProvider(config=flexipwn_config)

    try:
        provider.destroy(env_id)
    except Exception as exc:
        console.print(f"[yellow]Aviso al destruir entorno:[/yellow] {exc}")

    with get_session() as session:
        run = repository.get_run_by_env_id(session, env_id)
        if run and run.status == "running":
            repository.mark_run_finished(session, run_id, "stopped")

    console.print(f"[green]Run {env_id} detenido.[/green]")


@app.command("reset")
def run_reset(
    env_id: str = typer.Argument(..., help="env_id del run"),
    password: str = typer.Option(..., "--password", help="Contraseña del participante"),
) -> None:
    """Reinicia el entorno de un run preservando historial de targets."""
    with get_session() as session:
        run = repository.get_run_by_env_id(session, env_id)
        if run is None:
            console.print(f"[red]Run no encontrado:[/red] {env_id}")
            raise typer.Exit(1)

        db_participant = session.get(Participant, run.participant_id)
        if db_participant is None or not repository.verify_participant_password(db_participant, password):
            console.print("[red]Contraseña incorrecta.[/red]")
            raise typer.Exit(1)

        db_scenario = repository.get_scenario(session, run.scenario_id)
        if db_scenario is None:
            console.print("[red]Escenario no encontrado en DB.[/red]")
            raise typer.Exit(1)

        scenario_config = repository.parse_scenario_config(db_scenario)
        run_id = run.id
        scenario_db_id = run.scenario_id
        participant_id = run.participant_id

    with get_session() as session:
        repository.mark_targets_reset(session, run_id)

    flexipwn_config = FlexiPwnConfig()
    provider = DockerRootlessProvider(config=flexipwn_config)

    try:
        provider.destroy(env_id)
    except Exception as exc:
        console.print(f"[yellow]Aviso al destruir entorno:[/yellow] {exc}")

    try:
        docker_env = provider.create(
            scenario_id=str(scenario_db_id),
            participant_id=str(participant_id),
            image=scenario_config.environment.image,
            attacker_image=scenario_config.environment.attacker_image,
            ports=scenario_config.environment.ports or None,
            attacker_ports=scenario_config.environment.attacker_ports or None,
            log_paths=scenario_config.environment.log_paths or None,
            startup_delay=scenario_config.environment.startup_delay_seconds,
            enable_network_capture=any(
                t.type.startswith("network_") for t in scenario_config.targets
            ),
            capture_filter=scenario_config.environment.capture_filter,
        )
    except ImageNotFoundError:
        console.print(
            f"[red]Imagen no encontrada:[/red] {scenario_config.environment.image!r}"
        )
        raise typer.Exit(1)

    new_env_id = docker_env.env_id

    _inject_attacker_password(provider, new_env_id, password, docker_env.container_attacker_name)
    _inject_hints(provider, new_env_id, scenario_config.hints)

    with get_session() as session:
        run_db = session.get(ExerciseRun, run_id)
        if run_db:
            run_db.env_id = new_env_id
            run_db.status = "running"
            run_db.progress = 0.0
            run_db.started_at = _now()
            run_db.finished_at = None
            session.add(run_db)
            session.commit()
        repository.bulk_create_target_results(session, run_id, scenario_config)

    console.print(f"[green]Run reseteado.[/green] Nuevo env_id: [bold]{new_env_id}[/bold]")
    console.print(
        f"[dim]Inícialo de nuevo con:[/dim] [yellow]flexipwn run start "
        f"--scenario {scenario_db_id} --participant <username> --password <pw>[/yellow]"
    )


@app.command("watch")
def run_watch(env_id: str = typer.Argument(..., help="env_id del run")) -> None:
    """Muestra eventos del run en tiempo real (historial + nuevos). Ctrl+C para salir."""
    with get_session() as session:
        run = repository.get_run_by_env_id(session, env_id)
        if run is None:
            console.print(f"[red]Run no encontrado:[/red] {env_id}")
            raise typer.Exit(1)
        run_id = run.id

    console.print(f"[bold]Watching run:[/bold] {env_id} [dim](Ctrl+C para salir)[/dim]\n")

    with get_session() as session:
        events = repository.list_run_events(session, run_id)

    last_timestamp = None
    for ev in events:
        _print_event(ev)
        last_timestamp = ev.timestamp

    try:
        while True:
            time.sleep(1)
            with get_session() as session:
                new_events = repository.list_run_events(session, run_id, since=last_timestamp)
            for ev in new_events:
                _print_event(ev)
                last_timestamp = ev.timestamp
    except KeyboardInterrupt:
        console.print("\n[dim]Watch finalizado (el run sigue activo si está en marcha).[/dim]")


def _print_event(ev) -> None:
    ts = str(ev.timestamp)[:19]
    try:
        details = json.loads(ev.details_json)
        detail_str = (
            details.get("path")
            or details.get("cmd")
            or details.get("raw_line", "")[:80]
            or ""
        )
    except Exception:
        detail_str = ""
    console.print(
        f"[dim]{ts}[/dim] [{ev.monitor_type}] [cyan]{ev.event_type}[/cyan]"
        + (f"  {detail_str}" if detail_str else "")
    )


@app.command("list")
def run_list(
    scenario: str = typer.Option(None, "--scenario", help="Filtrar por UUID de escenario"),
    participant: str = typer.Option(None, "--participant", help="Filtrar por username"),
) -> None:
    """Lista runs con filtros opcionales."""
    sid = uuid.UUID(scenario) if scenario else None
    with get_session() as session:
        pid = None
        if participant:
            p = repository.get_participant_by_username(session, participant)
            if p is None:
                console.print(f"[red]Participante no encontrado:[/red] {participant!r}")
                raise typer.Exit(1)
            pid = p.id
        runs = repository.list_runs(session, scenario_id=sid, participant_id=pid)

    if not runs:
        console.print("[dim]No hay runs con los filtros aplicados.[/dim]")
        return

    table = Table(title="Runs", show_header=True)
    table.add_column("env_id", style="cyan")
    table.add_column("Estado")
    table.add_column("Progreso")
    table.add_column("Inicio")
    _colors = {
        "completed": "green", "failed": "red", "timeout": "red",
        "stopped": "yellow", "running": "cyan", "pending": "dim",
    }
    for r in runs:
        pct = f"{int(r.progress * 100)}%"
        inicio = str(r.started_at)[:19] if r.started_at else "—"
        color = _colors.get(r.status, "white")
        table.add_row(r.env_id, f"[{color}]{r.status}[/{color}]", pct, inicio)
    console.print(table)


@app.command("show")
def run_show(env_id: str = typer.Argument(..., help="env_id del run")) -> None:
    """Muestra detalles de un run incluyendo el estado de cada target."""
    with get_session() as session:
        run = repository.get_run_by_env_id(session, env_id)
        if run is None:
            console.print(f"[red]Run no encontrado:[/red] {env_id}")
            raise typer.Exit(1)
        run_id = run.id
        targets = repository.get_target_results(session, run_id)

    _colors = {
        "completed": "green", "running": "cyan", "pending": "dim",
        "failed": "red", "timeout": "red", "stopped": "yellow",
    }
    color = _colors.get(run.status, "white")

    console.print(Panel(
        f"[dim]env_id:[/dim]     [bold]{run.env_id}[/bold]\n"
        f"[dim]Estado:[/dim]     [{color}]{run.status}[/{color}]\n"
        f"[dim]Progreso:[/dim]   {int(run.progress * 100)}%\n"
        f"[dim]Iniciado:[/dim]   {str(run.started_at)[:19] if run.started_at else '—'}\n"
        f"[dim]Finalizado:[/dim] {str(run.finished_at)[:19] if run.finished_at else '—'}",
        title=f"Run {env_id}",
        border_style="cyan",
    ))

    activos = [t for t in targets if t.reset_at is None]
    previos = [t for t in targets if t.reset_at is not None]

    if activos:
        table = Table(title="Targets (intento actual)", show_header=True)
        table.add_column("#", style="dim", width=3)
        table.add_column("Tipo", style="cyan")
        table.add_column("Descripción")
        table.add_column("Matcheado")
        table.add_column("Momento")
        for t in sorted(activos, key=lambda x: x.target_index):
            matched_str = "[green]✓[/green]" if t.matched else "[dim]—[/dim]"
            matched_at = str(t.matched_at)[:19] if t.matched_at else "—"
            table.add_row(str(t.target_index + 1), t.target_type, t.description, matched_str, matched_at)
        console.print(table)

    if previos:
        table2 = Table(title="Targets (intentos anteriores)", show_header=True)
        table2.add_column("#", style="dim", width=3)
        table2.add_column("Tipo", style="cyan", no_wrap=True)
        table2.add_column("Descripción")
        table2.add_column("Matcheado")
        table2.add_column("Reseteado")
        for t in sorted(previos, key=lambda x: x.target_index):
            matched_str = "[green]✓[/green]" if t.matched else "[dim]—[/dim]"
            reset_at = str(t.reset_at)[:19] if t.reset_at else "—"
            table2.add_row(str(t.target_index + 1), t.target_type, t.description, matched_str, reset_at)
        console.print(table2)
