from __future__ import annotations

import csv
import json
import time
import uuid
from pathlib import Path
from typing import Callable

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from flexipwn.config import FlexiPwnConfig
from flexipwn.layer1.docker_rootless import DockerRootlessProvider
from flexipwn.layer1.provider import ImageNotFoundError
from flexipwn.layer3.schema import scenario_requires_network_capture
from flexipwn.layer4.cli.daemon import require_daemon
from flexipwn.layer4.core.port_allocator import find_free_port
from flexipwn.layer4.db import repository
from flexipwn.layer4.db.models import ExerciseRun, Participant
from flexipwn.layer4.db.session import get_session

app = typer.Typer(help="Gestión de runs")
console = Console()

DAEMON_CRED_TIMEOUT_SECONDS = 30
BATCH_CRED_TIMEOUT_SECONDS = 60


class ProvisionError(Exception):
    """Falla al aprovisionar un entorno.

    `_provision_environment` la lanza en vez de cortar el proceso: `run start`
    la traduce a `typer.Exit`, mientras que `batch-start` la captura para
    registrar el fallo y seguir con el siguiente entorno. `message` ya viene
    con markup Rich listo para imprimir.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pick_scenario_interactive() -> uuid.UUID:
    with get_session() as session:
        scenarios = repository.list_scenarios(session)
    if not scenarios:
        console.print(
            "[red]No hay escenarios cargados.[/red] "
            "Carga uno con: [yellow]flexipwn scenario load <yaml>[/yellow]"
        )
        raise typer.Exit(1)
    table = Table(title="Escenarios disponibles", show_header=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Título", style="cyan")
    table.add_column("Categoría")
    table.add_column("Nivel")
    for i, s in enumerate(scenarios, 1):
        table.add_row(str(i), s.title, s.category, s.level)
    console.print(table)
    idx = typer.prompt("Selecciona el número del escenario", type=int)
    if idx < 1 or idx > len(scenarios):
        console.print("[red]Selección inválida.[/red]")
        raise typer.Exit(1)
    return scenarios[idx - 1].id


def _pick_participant_interactive() -> uuid.UUID:
    with get_session() as session:
        participants = repository.list_participants(session)
    if not participants:
        console.print(
            "[red]No hay participantes.[/red] "
            "Crea uno con: [yellow]flexipwn participant add[/yellow]"
        )
        raise typer.Exit(1)
    table = Table(title="Participantes", show_header=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Username", style="cyan")
    table.add_column("Creado")
    for i, p in enumerate(participants, 1):
        table.add_row(str(i), p.username, str(p.created_at)[:19])
    console.print(table)
    idx = typer.prompt("Selecciona el número del participante", type=int)
    if idx < 1 or idx > len(participants):
        console.print("[red]Selección inválida.[/red]")
        raise typer.Exit(1)
    return participants[idx - 1].id


def _resolve_scenario(scenario_arg: str) -> uuid.UUID:
    """Acepta UUID o título del escenario."""
    try:
        return uuid.UUID(scenario_arg)
    except ValueError:
        pass
    with get_session() as session:
        scenarios = repository.list_scenarios(session)
    for s in scenarios:
        if s.title == scenario_arg:
            return s.id
    console.print(f"[red]Escenario no encontrado:[/red] {scenario_arg!r}")
    raise typer.Exit(1)


def _resolve_participant(participant_arg: str) -> uuid.UUID:
    with get_session() as session:
        p = repository.get_participant_by_username(session, participant_arg)
    if p is None:
        console.print(f"[red]Participante no encontrado:[/red] {participant_arg!r}")
        raise typer.Exit(1)
    return p.id


def _provision_environment(
    scenario_id: uuid.UUID, participant_id: uuid.UUID, config: FlexiPwnConfig
) -> tuple[str, int, uuid.UUID]:
    """Aloca puerto, crea entorno Docker, registra el run en DB.

    Devuelve (env_id, ssh_port, run_id).
    """
    with get_session() as session:
        scenario = repository.get_scenario(session, scenario_id)
        if scenario is None:
            raise ProvisionError("[red]Escenario no encontrado en DB.[/red]")
        scenario_config = repository.parse_scenario_config(scenario)
        scenario_db_id = scenario.id

    if scenario_config.environment.attacker_image is None:
        raise ProvisionError(
            f"[red]El escenario {scenario_config.title!r} no tiene imagen "
            f"atacante definida.[/red]\n"
            "Los estudiantes deben conectarse por SSH al contenedor atacante. "
            "Agrega [yellow]attacker_image: flexipwn/attacker[/yellow] al "
            "YAML del escenario."
        )

    try:
        ssh_port = find_free_port(
            config.attacker_port_range_start, config.attacker_port_range_end
        )
    except RuntimeError as exc:
        raise ProvisionError(f"[red]{exc}[/red]")

    provider = DockerRootlessProvider(config=config)

    console.print(
        f"[bold]Iniciando entorno...[/bold] "
        f"[dim](timeout: {scenario_config.timeout_seconds}s, "
        f"puerto SSH host: {ssh_port})[/dim]"
    )
    try:
        docker_env = provider.create(
            scenario_id=str(scenario_db_id),
            participant_id=str(participant_id),
            image=scenario_config.environment.image,
            attacker_image=scenario_config.environment.attacker_image,
            ports=scenario_config.environment.ports or None,
            attacker_ports=[f"{ssh_port}:22"],
            log_paths=scenario_config.environment.log_paths or None,
            startup_delay=scenario_config.environment.startup_delay_seconds,
            enable_network_capture=scenario_requires_network_capture(
                scenario_config
            ),
            capture_filter=scenario_config.environment.capture_filter,
        )
    except ImageNotFoundError as exc:
        raise ProvisionError(f"[red]{exc}[/red]")
    except Exception as exc:
        raise ProvisionError(f"[red]Error creando entorno:[/red] {exc}")

    env_id = docker_env.env_id

    with get_session() as session:
        run = repository.create_run(
            session, scenario_db_id, participant_id, env_id,
            attacker_ssh_port=ssh_port,
        )
        run_id = run.id
        repository.mark_run_started(session, run_id, attacker_ssh_port=ssh_port)
        repository.bulk_create_target_results(session, run_id, scenario_config)

    return env_id, ssh_port, run_id


def _wait_for_credentials(run_id: uuid.UUID, timeout_seconds: int) -> tuple[str | None, str | None]:
    """Hace polling de la DB hasta `timeout_seconds` esperando que el daemon
    popule attacker_ssh_username/attacker_ssh_password. Devuelve (user, pass)
    o (None, None) si el timeout se cumple.
    """
    deadline = time.monotonic() + timeout_seconds
    # Mensaje único en vez de console.status() — el spinner Rich no se
    # renderiza bien sobre el socket de `daemon attach` (cada frame llega
    # como línea nueva).
    console.print("[cyan]Esperando configuración SSH del daemon...[/cyan]")
    while time.monotonic() < deadline:
        with get_session() as session:
            run = session.get(ExerciseRun, run_id)
            if run and run.attacker_ssh_username and run.attacker_ssh_password:
                return run.attacker_ssh_username, run.attacker_ssh_password
        time.sleep(0.5)
    return None, None


def _print_ssh_instruction(host: str, port: int, username: str, password: str) -> None:
    sep = "─" * 58
    console.print(
        Panel.fit(
            f"Host:     {host}\n"
            f"Puerto:   {port}\n"
            f"Usuario:  {username}\n"
            f"Clave:    {password}    [dim](solo visible en este momento)[/dim]\n"
            f"Comando:  [bold]ssh {username}@{host} -p {port}[/bold]",
            title="Acceso del estudiante",
            border_style="green",
        )
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command("start")
def run_start(
    scenario: str | None = typer.Option(
        None, "--scenario", help="UUID o título del escenario"
    ),
    participant: str | None = typer.Option(
        None, "--participant", help="Username del participante"
    ),
) -> None:
    """Inicia un run de ejercicio. Sin argumentos, lanza el wizard interactivo."""
    require_daemon()

    if scenario is None and participant is None:
        scenario_id = _pick_scenario_interactive()
        participant_id = _pick_participant_interactive()
    else:
        if scenario is None or participant is None:
            console.print(
                "[red]Si pasas alguno de --scenario o --participant, debes pasar ambos.[/red]"
            )
            raise typer.Exit(1)
        scenario_id = _resolve_scenario(scenario)
        participant_id = _resolve_participant(participant)

    config = FlexiPwnConfig()
    try:
        env_id, ssh_port, run_id = _provision_environment(
            scenario_id, participant_id, config
        )
    except ProvisionError as exc:
        console.print(exc.message)
        raise typer.Exit(1)

    console.print(f"\n[green]Entorno activo:[/green] [bold]{env_id}[/bold]")
    username, password = _wait_for_credentials(run_id, DAEMON_CRED_TIMEOUT_SECONDS)
    if username and password:
        _print_ssh_instruction(config.host, ssh_port, username, password)
    else:
        console.print(
            f"[yellow]El daemon no publicó las credenciales SSH en "
            f"{DAEMON_CRED_TIMEOUT_SECONDS} segundos.[/yellow]\n"
            f"El entorno está corriendo (env_id: {env_id}).\n"
            f"Consulta las credenciales más tarde con: "
            f"[yellow]flexipwn run show {env_id}[/yellow]\n"
            f"O revisa el estado del daemon con: "
            f"[yellow]flexipwn daemon logs[/yellow]"
        )


@app.command("batch-start")
def run_batch_start(
    assignments_file: str = typer.Argument(..., help="YAML con asignaciones."),
    output: str | None = typer.Option(
        None, "--output", help="Si se especifica, escribe CSV con scenario,username,env_id,ssh_port,ssh_password."
    ),
) -> None:
    """Crea múltiples runs en paralelo a partir de un archivo de asignaciones."""
    require_daemon()

    yaml_path = Path(assignments_file)
    if not yaml_path.exists():
        console.print(f"[red]Archivo no encontrado:[/red] {assignments_file}")
        raise typer.Exit(1)
    try:
        raw = yaml.safe_load(yaml_path.read_text())
    except Exception as exc:
        console.print(f"[red]Error parseando YAML:[/red] {exc}")
        raise typer.Exit(1)
    assignments = (raw or {}).get("assignments")
    if not assignments:
        console.print("[red]El YAML debe tener una clave 'assignments' con lista de entradas.[/red]")
        raise typer.Exit(1)

    # Validar todos los escenarios existen y tienen attacker_image
    config = FlexiPwnConfig()
    expanded: list[tuple[str, uuid.UUID]] = []  # (scenario_title, scenario_id)
    with get_session() as session:
        all_scenarios = repository.list_scenarios(session)
    by_title = {s.title: s for s in all_scenarios}
    for entry in assignments:
        title = entry.get("scenario")
        count = int(entry.get("count", 0))
        if not title or count <= 0:
            console.print(f"[red]Entrada inválida:[/red] {entry}")
            raise typer.Exit(1)
        scenario = by_title.get(title)
        if scenario is None:
            console.print(f"[red]Escenario no encontrado en DB:[/red] {title!r}")
            raise typer.Exit(1)
        if not scenario.attacker_image:
            console.print(
                f"[red]El escenario {title!r} no tiene attacker_image.[/red]"
            )
            raise typer.Exit(1)
        for _ in range(count):
            expanded.append((title, scenario.id))

    # Ejecutar secuencialmente. Un fallo al aprovisionar un entorno NO aborta
    # el batch: se registra y se sigue con el siguiente (política continue-on-error).
    rows: list[dict] = []
    failures: list[dict] = []
    for i, (title, scenario_id) in enumerate(expanded, 1):
        console.print(f"\n[bold]({i}/{len(expanded)})[/bold] {title}")
        with get_session() as session:
            participant, _plaintext = repository.create_participant(session)
            participant_id = participant.id
            username = participant.username

        try:
            env_id, ssh_port, run_id = _provision_environment(
                scenario_id, participant_id, config
            )
        except ProvisionError as exc:
            # Limpia el participante huérfano: se creó antes de saber que el
            # aprovisionamiento fallaría, y sin run asociado no sirve de nada.
            with get_session() as session:
                repository.delete_participant(session, participant_id)
            reason = Text.from_markup(exc.message).plain
            console.print(f"  [red]✗ Falló:[/red] {exc.message}")
            failures.append(
                {"scenario": title, "username": username, "error": reason}
            )
            continue

        rows.append(
            {
                "scenario": title,
                "username": username,
                "env_id": env_id,
                "ssh_port": ssh_port,
                "run_id": run_id,
                "ssh_password": None,
            }
        )

    # Esperar credenciales del daemon (solo para los entornos que sí se crearon)
    if rows:
        deadline = time.monotonic() + BATCH_CRED_TIMEOUT_SECONDS
        pending = {row["run_id"]: row for row in rows}
        console.print(
            "[cyan]Esperando que el daemon publique credenciales SSH...[/cyan]"
        )
        while pending and time.monotonic() < deadline:
            with get_session() as session:
                for run_id, row in list(pending.items()):
                    run = session.get(ExerciseRun, run_id)
                    if run and run.attacker_ssh_password:
                        row["ssh_password"] = run.attacker_ssh_password
                        pending.pop(run_id)
            if pending:
                time.sleep(1.0)

    # Tabla de asignaciones creadas
    if rows:
        table = Table(title="Asignaciones creadas", show_header=True)
        table.add_column("Escenario", style="cyan")
        table.add_column("Usuario")
        table.add_column("env_id", style="dim")
        table.add_column("Puerto SSH")
        table.add_column("Clave SSH")
        for row in rows:
            pw = row["ssh_password"] or "[yellow]pendiente[/yellow]"
            table.add_row(
                row["scenario"], row["username"], row["env_id"],
                str(row["ssh_port"]), pw,
            )
        console.print(table)

    # Tabla de fallos
    if failures:
        ftable = Table(title="Fallos", show_header=True, border_style="red")
        ftable.add_column("Escenario", style="cyan")
        ftable.add_column("Usuario")
        ftable.add_column("Motivo", style="red")
        for f in failures:
            ftable.add_row(f["scenario"], f["username"], f["error"])
        console.print(ftable)

    # Resumen
    total = len(expanded)
    console.print(
        f"\n[bold]Resumen:[/bold] "
        f"[green]{len(rows)} creado(s)[/green], "
        f"[red]{len(failures)} fallido(s)[/red] de {total}."
    )

    if output:
        out_path = Path(output)
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["scenario", "username", "env_id", "ssh_port", "ssh_password", "status", "error"]
            )
            for row in rows:
                writer.writerow(
                    [
                        row["scenario"],
                        row["username"],
                        row["env_id"],
                        row["ssh_port"],
                        row["ssh_password"] or "",
                        "created",
                        "",
                    ]
                )
            for fail in failures:
                writer.writerow(
                    [fail["scenario"], fail["username"], "", "", "", "failed", fail["error"]]
                )
        console.print(f"\n[green]CSV escrito:[/green] {out_path}")
        if any(r["ssh_password"] is None for r in rows):
            console.print(
                "[yellow]Aviso:[/yellow] algunas filas no tienen contraseña; "
                "consulta `flexipwn run show <env_id>` cuando el daemon termine."
            )


@app.command("stop")
def run_stop(env_id: str = typer.Argument(..., help="env_id del run")) -> None:
    """Solicita al daemon detener el run y destruir su entorno."""
    require_daemon()
    with get_session() as session:
        run = repository.get_run_by_env_id(session, env_id)
        if run is None:
            console.print(f"[red]Run no encontrado:[/red] {env_id}")
            raise typer.Exit(1)
        repository.set_run_status(session, run.id, "stopping")
    console.print(
        f"[green]Stop solicitado para {env_id}.[/green] "
        f"El daemon limpiará en breve."
    )


@app.command("reset")
def run_reset(env_id: str = typer.Argument(..., help="env_id del run")) -> None:
    """Solicita al daemon resetear el entorno preservando el historial de targets."""
    require_daemon()
    with get_session() as session:
        run = repository.get_run_by_env_id(session, env_id)
        if run is None:
            console.print(f"[red]Run no encontrado:[/red] {env_id}")
            raise typer.Exit(1)
        scenario = repository.get_scenario(session, run.scenario_id)
        if scenario is None:
            console.print("[red]Escenario no encontrado en DB.[/red]")
            raise typer.Exit(1)
        scenario_config = repository.parse_scenario_config(scenario)
        run_id = run.id
        repository.mark_targets_reset(session, run_id)

        payload = {
            "image": scenario_config.environment.image,
            "attacker_image": scenario_config.environment.attacker_image,
            "ports": scenario_config.environment.ports,
            "log_paths": scenario_config.environment.log_paths,
            "capture_filter": scenario_config.environment.capture_filter,
            "startup_delay_seconds": scenario_config.environment.startup_delay_seconds,
        }
        repository.set_reset_payload(session, run_id, json.dumps(payload))
        repository.set_run_status(session, run_id, "resetting")

    console.print(
        f"[green]Reset solicitado para {env_id}.[/green] "
        f"El daemon recreará el entorno y publicará nuevas credenciales."
    )


def _perform_run_removal(env_id: str, confirm: Callable[[str], bool]) -> bool:
    """Guard + teardown de contenedores + borrado en DB de un run terminal.

    `confirm` abstrae la única diferencia entre frontends (typer.confirm en la
    CLI standalone vs. el prompter del REPL/socket). Devuelve True si se eliminó.
    """
    with get_session() as session:
        run = repository.get_run_by_env_id(session, env_id)
        if run is None:
            console.print(f"[red]Run no encontrado:[/red] {env_id}")
            return False
        if run.status not in repository.TERMINAL_STATUSES:
            console.print(
                f"[red]No se puede eliminar un run en estado {run.status!r}.[/red]\n"
                f"Debe estar terminado. Detenlo con "
                f"[yellow]run stop {env_id}[/yellow] primero."
            )
            return False
        run_id, status = run.id, run.status
    if not confirm(
        f"¿Eliminar run {env_id} (estado {status})? Borra DB y contenedores."
    ):
        console.print("[dim]Cancelado.[/dim]")
        return False
    # Teardown defensivo: en estado terminal el daemon ya destruyó el entorno,
    # pero destroy() es idempotente y limpia cualquier residuo (contenedores,
    # redes, volúmenes) aunque el daemon no esté corriendo.
    try:
        DockerRootlessProvider(config=FlexiPwnConfig()).destroy(env_id)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]Aviso al destruir contenedores:[/yellow] {exc}")
    with get_session() as session:
        repository.delete_run(session, run_id)
    console.print(f"[green]Run {env_id} eliminado (DB + contenedores).[/green]")
    return True


@app.command("remove")
def run_remove(
    env_id: str = typer.Argument(..., help="env_id del run"),
    yes: bool = typer.Option(False, "--yes", "-y", help="No pedir confirmación."),
) -> None:
    """Elimina por completo un run terminal (registro en DB + contenedores)."""
    _perform_run_removal(env_id, confirm=lambda msg: yes or typer.confirm(msg))


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
    """Lista runs con contexto (scenario + participant + ssh_port)."""
    sid = uuid.UUID(scenario) if scenario else None
    with get_session() as session:
        pid = None
        if participant:
            p = repository.get_participant_by_username(session, participant)
            if p is None:
                console.print(f"[red]Participante no encontrado:[/red] {participant!r}")
                raise typer.Exit(1)
            pid = p.id
        rows = repository.list_runs_with_context(
            session, scenario_id=sid, participant_id=pid
        )

    if not rows:
        console.print("[dim]No hay runs con los filtros aplicados.[/dim]")
        return

    table = Table(title="Runs", show_header=True)
    table.add_column("env_id", style="cyan")
    table.add_column("Escenario")
    table.add_column("Participante")
    table.add_column("Estado")
    table.add_column("Progreso")
    table.add_column("Puerto SSH")
    table.add_column("Inicio")
    _colors = {
        "completed": "green", "failed": "red", "timeout": "red",
        "stopped": "yellow", "running": "cyan", "pending": "dim",
        "stopping": "yellow", "resetting": "yellow",
    }
    for r in rows:
        pct = f"{int((r['progress'] or 0) * 100)}%"
        inicio = str(r["started_at"])[:19] if r["started_at"] else "—"
        port = str(r["attacker_ssh_port"]) if r["attacker_ssh_port"] else "—"
        color = _colors.get(r["status"], "white")
        table.add_row(
            r["env_id"],
            r["scenario_title"],
            r["participant_username"],
            f"[{color}]{r['status']}[/{color}]",
            pct,
            port,
            inicio,
        )
    console.print(table)


@app.command("show")
def run_show(env_id: str = typer.Argument(..., help="env_id del run")) -> None:
    """Muestra detalles del run con historial de intentos."""
    with get_session() as session:
        run = repository.get_run_by_env_id(session, env_id)
        if run is None:
            console.print(f"[red]Run no encontrado:[/red] {env_id}")
            raise typer.Exit(1)
        scenario = repository.get_scenario(session, run.scenario_id)
        participant = session.get(Participant, run.participant_id)
        targets = repository.get_target_results_by_run(session, run.id)

    _colors = {
        "completed": "green", "running": "cyan", "pending": "dim",
        "failed": "red", "timeout": "red", "stopped": "yellow",
        "stopping": "yellow", "resetting": "yellow",
    }
    color = _colors.get(run.status, "white")

    ssh_lines = ""
    if run.attacker_ssh_username and run.attacker_ssh_password and run.attacker_ssh_port:
        ssh_lines = (
            f"\n[dim]SSH host:[/dim] {FlexiPwnConfig().host}"
            f"\n[dim]SSH port:[/dim] {run.attacker_ssh_port}"
            f"\n[dim]SSH user:[/dim] {run.attacker_ssh_username}"
            f"\n[dim]SSH pass:[/dim] {run.attacker_ssh_password}"
        )

    panel_body = (
        f"[dim]Run ID:[/dim]      [bold]{run.id}[/bold]\n"
        f"[dim]Scenario:[/dim]    {scenario.title if scenario else '—'}\n"
        f"[dim]Participant:[/dim] {participant.username if participant else '—'}\n"
        f"[dim]Estado:[/dim]      [{color}]{run.status}[/{color}]\n"
        f"[dim]Progreso:[/dim]    {int(run.progress * 100)}%\n"
        f"[dim]Iniciado:[/dim]    {str(run.started_at)[:19] if run.started_at else '—'}\n"
        f"[dim]Finalizado:[/dim]  {str(run.finished_at)[:19] if run.finished_at else '—'}"
        + ssh_lines
    )
    console.print(Panel(panel_body, title=f"Run {env_id}", border_style="cyan"))

    # Agrupar targets por reset_at; None = intento actual; cada timestamp = intento previo.
    groups: dict[str, list] = {}
    for t in targets:
        key = "actual" if t.reset_at is None else str(t.reset_at)[:19]
        groups.setdefault(key, []).append(t)

    # Imprimir intentos previos primero (orden cronológico)
    for key in sorted(k for k in groups if k != "actual"):
        title = f"Intento anterior (env_id: {run.env_id}, reseteado {key})"
        _print_target_table(title, groups[key], previous=True)

    if "actual" in groups:
        _print_target_table("Intento actual", groups["actual"], previous=False)


def _print_target_table(title: str, targets: list, *, previous: bool) -> None:
    table = Table(title=title, show_header=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Tipo", style="cyan")
    table.add_column("Descripción")
    table.add_column("Estado")
    table.add_column("Momento")
    for t in sorted(targets, key=lambda x: x.target_index):
        if t.matched:
            state = "[green]✓[/green]"
            when = str(t.matched_at)[:19] if t.matched_at else "—"
        else:
            state = (
                "[dim]no completado[/dim]" if previous else "[yellow]pendiente[/yellow]"
            )
            when = (
                str(t.reset_at)[:19] if previous and t.reset_at else "—"
            )
        table.add_row(str(t.target_index + 1), t.target_type, t.description, state, when)
    console.print(table)


@app.command("progress")
def run_progress(env_id: str = typer.Argument(..., help="env_id del run")) -> None:
    """Imprime el estado actual de los targets del run."""
    with get_session() as session:
        run = repository.get_run_by_env_id(session, env_id)
        if run is None:
            console.print(f"[red]Run no encontrado:[/red] {env_id}")
            raise typer.Exit(1)
        targets = repository.get_target_results_by_run(session, run.id)

    actuales = [t for t in targets if t.reset_at is None]
    matched = [t for t in actuales if t.matched]
    total = len(actuales)
    pct = int((len(matched) / total) * 100) if total else 0

    for t in sorted(actuales, key=lambda x: x.target_index):
        marker = "[green]✓[/green]" if t.matched else "[red]✗[/red]"
        when = f" ({str(t.matched_at)[:19]})" if t.matched and t.matched_at else " (pendiente)"
        console.print(f"  {marker} [cyan]{t.target_type}[/cyan]: {t.description}{when}")

    console.print(f"\n[bold]Progreso: {len(matched)}/{total} ({pct}%)[/bold]")
