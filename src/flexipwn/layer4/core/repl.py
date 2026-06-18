"""REPL interactivo para `flexipwn daemon start` (foreground).

Comparte proceso con el DaemonLoop: el loop corre en un thread daemonio y el
REPL en el thread principal. La salida de Rich del DaemonLoop se intercala
sobre el prompt vía `prompt_toolkit.patch_stdout`.
"""
from __future__ import annotations

import os
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import typer
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, NestedCompleter, PathCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.patch_stdout import patch_stdout
from rich.console import Console
from rich.table import Table

# --------------------------------------------------------------------------
# Redirección de Console por-thread.
#
# Cada handler del REPL (foreground o attach) corre en su propio thread y
# necesita que la salida de los módulos CLI (`console.print(...)`) vaya a
# SU console. Antes usábamos un lock global y mutábamos `module.console`,
# pero un comando largo (ej. run watch) bloqueaba dispatches concurrentes.
#
# Diseño actual: instalar UNA VEZ un Console-proxy por módulo que delega a
# un Console thread-local si está configurado, y al original si no. Sin
# locks, cada thread ve su propio destino.
# --------------------------------------------------------------------------

_thread_console = threading.local()
_proxies_installed = False
_install_lock = threading.Lock()


class _ConsoleProxy:
    """Proxy de rich.Console que delega a un Console thread-local si existe."""

    __slots__ = ("_default",)

    def __init__(self, default: Console) -> None:
        object.__setattr__(self, "_default", default)

    def _target(self) -> Console:
        target = getattr(_thread_console, "current", None)
        if target is None or target is self:
            return self._default
        # Defensa contra anidamiento: desenvuelve proxies hasta llegar a un
        # Console real.
        while isinstance(target, _ConsoleProxy):
            target = target._default
        return target

    def __getattr__(self, name: str):
        return getattr(self._target(), name)

    def __setattr__(self, name: str, value) -> None:
        setattr(self._target(), name, value)


def _install_console_proxies() -> None:
    """Reemplaza el `console` de cada módulo CLI por un _ConsoleProxy."""
    global _proxies_installed
    if _proxies_installed:
        return
    with _install_lock:
        if _proxies_installed:
            return
        from flexipwn.layer4.cli import cleanup as cleanup_mod
        from flexipwn.layer4.cli import daemon as daemon_mod
        from flexipwn.layer4.cli import participant as participant_mod
        from flexipwn.layer4.cli import run as run_mod
        from flexipwn.layer4.cli import scenario as scenario_mod

        for mod in (scenario_mod, participant_mod, run_mod, daemon_mod, cleanup_mod):
            if not isinstance(mod.console, _ConsoleProxy):
                mod.console = _ConsoleProxy(mod.console)
        _proxies_installed = True


@contextmanager
def _redirect_cli_consoles(target: Console):
    """Configura `target` como el Console activo para este thread."""
    _install_console_proxies()
    prev = getattr(_thread_console, "current", None)
    _thread_console.current = target
    try:
        yield
    finally:
        _thread_console.current = prev


# --------------------------------------------------------------------------
# Cancel event por-thread (para que comandos largos detecten desconexión).
# --------------------------------------------------------------------------

_thread_cancel = threading.local()


@contextmanager
def use_cancel_event(event: threading.Event):
    """Expone un Event de cancelación al handler corriendo en este thread."""
    prev = getattr(_thread_cancel, "event", None)
    _thread_cancel.event = event
    try:
        yield
    finally:
        _thread_cancel.event = prev


def _current_cancel_event() -> threading.Event | None:
    return getattr(_thread_cancel, "event", None)

from flexipwn.config import FlexiPwnConfig
from flexipwn.layer4.core.daemon_loop import DaemonLoop
from flexipwn.layer4.db import repository
from flexipwn.layer4.db.session import get_session

CommandHandler = Callable[[list[str]], None]

_HELP_TEXT = """\
Comandos disponibles:

  scenario list                       — lista escenarios cargados
  scenario load <yaml>                — carga un escenario YAML
  scenario show <id>                  — detalle de un escenario
  scenario remove <id> [--yes]        — elimina un escenario terminal (definición + runs + contenedores)
  scenario reset-all                  — limpia TODO el laboratorio (conserva participantes)

  participant add                     — crea un participante
  participant list                    — lista participantes
  participant reset-password <user>   — genera nueva contraseña
  participant remove <username>       — elimina (si no tiene runs activos)
  participant reset-all               — limpia TODO el laboratorio (conserva escenarios)

  run start                           — wizard: elige escenario + participante
  run stop <env_id>                   — detiene un run y destruye su entorno
  run reset <env_id>                  — recrea entorno preservando historial
  run remove <env_id>                 — elimina un run terminal (DB + contenedores)
  run list                            — runs con contexto y estado
  run show <env_id>                   — detalle del run
  run progress <env_id>               — estado de targets (snapshot)
  run watch <env_id>                  — eventos en tiempo real (Ctrl+C sale)
  run batch-start <yaml>              — crea runs masivos desde YAML

  dashboard [--all]                   — estado de entornos activos (--all: + terminados hoy)
  feed [--all]                        — registro de hitos cumplidos (hoy; --all: historial)
  daemon status                       — runs activos en este daemon

  clear                               — limpia la pantalla
  help                                — esta ayuda
  exit | quit                         — sale del REPL y detiene el daemon
"""


# Comandos completables con TAB. Mantener en sync con _build_handlers y
# _HELP_TEXT (exit/quit no son handlers pero se aceptan en el loop).
_COMPLETION_COMMANDS = (
    "help",
    "clear",
    "scenario list",
    "scenario load",
    "scenario show",
    "scenario remove",
    "scenario reset-all",
    "participant add",
    "participant list",
    "participant remove",
    "participant reset-password",
    "participant reset-all",
    "run start",
    "run stop",
    "run reset",
    "run remove",
    "run list",
    "run show",
    "run progress",
    "run watch",
    "run batch-start",
    "dashboard",
    "feed",
    "daemon status",
    "exit",
    "quit",
)
# Comandos cuyo argumento es una ruta a un YAML → completado de archivos.
_PATH_COMMANDS = frozenset({"scenario load", "run batch-start"})


def _is_yaml_or_dir(path: str) -> bool:
    """Filtro de PathCompleter: muestra directorios (para navegar) y YAMLs."""
    return os.path.isdir(path) or path.endswith((".yaml", ".yml"))


def build_repl_completer() -> Completer:
    """Completer de TAB compartido por el REPL foreground y el cliente attach.

    Completa nombres de comando (anidados: ``run`` → ``start``/``stop``/…) y,
    en los comandos que reciben un YAML, delega a completado de rutas.
    """
    yaml_completer = PathCompleter(expanduser=True, file_filter=_is_yaml_or_dir)
    tree: dict[str, object] = {}
    for cmd in _COMPLETION_COMMANDS:
        parts = cmd.split()
        node: dict[str, object] = tree
        for depth, part in enumerate(parts):
            if depth == len(parts) - 1:
                node[part] = yaml_completer if cmd in _PATH_COMMANDS else None
            else:
                child = node.get(part)
                if not isinstance(child, dict):
                    child = {}
                    node[part] = child
                node = child
    return NestedCompleter.from_nested_dict(tree)


# --------------------------------------------------------------------------
# Badge de novedades del prompt (compartido por el REPL foreground y el
# cliente attach). Lee de la DB la cantidad de hitos posteriores al cursor de
# última lectura y los entornos activos. Pensado para `bottom_toolbar` de
# prompt_toolkit con `refresh_interval`, que repinta sin romper el prompt.
# --------------------------------------------------------------------------

def feed_badge_text(cursor: datetime) -> str:
    try:
        with get_session() as session:
            nuevas = repository.count_new_milestones(session, cursor)
            activos = repository.count_active_envs(session)
    except Exception:
        return ""
    nov = f"▲ {nuevas} nuevas" if nuevas else "sin novedades"
    return f" {nov} · {activos} entornos activos · feed para ver "


def is_feed_command(line: str) -> bool:
    """True si la línea abre el feed (entonces el cursor se avanza a ahora)."""
    return line == "feed" or line.startswith("feed ")


class FlexiPwnREPL:
    """REPL interactivo in-process. Comparte estado (DB) con el DaemonLoop."""

    def __init__(
        self,
        loop: DaemonLoop,
        console: Console,
        history_path: Path | None = None,
        stop_loop_on_exit: bool = True,
        prompter: Callable[[str], str] | None = None,
    ) -> None:
        self.loop = loop
        self.console = console
        self.stop_loop_on_exit = stop_loop_on_exit
        if history_path is None:
            history_path = Path.home() / ".flexipwn" / "history"
            history_path.parent.mkdir(parents=True, exist_ok=True)
        self.session: PromptSession[str] = PromptSession(
            history=FileHistory(str(history_path)),
            completer=build_repl_completer(),
            complete_while_typing=False,
        )
        # Prompter inyectable: foreground usa session.prompt; el server de socket
        # lo reemplaza por uno que viaja por el protocolo (PROMPT/INPUT).
        self._prompter: Callable[[str], str] = prompter or (
            lambda text: self.session.prompt(text)
        )
        self.handlers: dict[str, CommandHandler] = self._build_handlers()
        # Orden por longitud descendente para que "run batch-start" matchee
        # antes de "run" o "run start".
        self._dispatch_order = sorted(self.handlers, key=len, reverse=True)
        # Cursor de "última lectura" del feed, por cliente/instancia y en
        # memoria (decisión: consumo no-destructivo). El badge cuenta los
        # hitos posteriores a este timestamp; abrir `feed` lo avanza a ahora.
        self._feed_cursor: datetime = datetime.now(UTC)

    # ------------------------------------------------------------------
    # Handler registry
    # ------------------------------------------------------------------

    def _build_handlers(self) -> dict[str, CommandHandler]:
        return {
            "help": self._cmd_help,
            "clear": self._cmd_clear,
            "scenario list": self._cmd_scenario_list,
            "scenario load": self._cmd_scenario_load,
            "scenario show": self._cmd_scenario_show,
            "scenario remove": self._cmd_scenario_remove,
            "scenario reset-all": self._cmd_scenario_reset_all,
            "participant add": self._cmd_participant_add,
            "participant list": self._cmd_participant_list,
            "participant remove": self._cmd_participant_remove,
            "participant reset-password": self._cmd_participant_reset_password,
            "participant reset-all": self._cmd_participant_reset_all,
            "run start": self._cmd_run_start,
            "run stop": self._cmd_run_stop,
            "run reset": self._cmd_run_reset,
            "run remove": self._cmd_run_remove,
            "run list": self._cmd_run_list,
            "run show": self._cmd_run_show,
            "run progress": self._cmd_run_progress,
            "run watch": self._cmd_run_watch,
            "run batch-start": self._cmd_run_batch_start,
            "dashboard": self._cmd_dashboard,
            "feed": self._cmd_feed,
            "daemon status": self._cmd_daemon_status,
        }

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self) -> None:
        self.console.print(
            "[green]FlexiPwn daemon iniciado.[/green] "
            "Escribe 'help' para ver comandos."
        )
        try:
            # raw=True preserva los ANSI escapes de Rich (colores, highlight,
            # tablas, paneles); con el default los outputs se escapan literal.
            with patch_stdout(raw=True):
                while True:
                    try:
                        text = self.session.prompt(
                            "flexipwn> ",
                            bottom_toolbar=lambda: feed_badge_text(self._feed_cursor),
                            refresh_interval=2.0,
                        )
                    except KeyboardInterrupt:
                        continue            # Ctrl+C cancela la línea
                    except EOFError:
                        break                # Ctrl+D sale
                    stripped = text.strip()
                    if not stripped:
                        continue
                    if stripped in ("exit", "quit"):
                        break
                    self.dispatch_line(stripped)
                    # Abrir el feed marca todo lo previo como leído (cursor
                    # en memoria, no destructivo: otros clientes no se afectan).
                    if is_feed_command(stripped):
                        self._feed_cursor = datetime.now(UTC)
        finally:
            self.console.print("[yellow]Saliendo del REPL...[/yellow]")
            if self.stop_loop_on_exit:
                self.loop.stop()

    def dispatch_line(self, line: str) -> None:
        for prefix in self._dispatch_order:
            if line == prefix or line.startswith(prefix + " "):
                rest = line[len(prefix):].strip()
                args = rest.split() if rest else []
                # Redirige los consoles de los módulos CLI a self.console
                # para que la salida llegue al destino del REPL (terminal
                # foreground o socket attach) en vez de a sys.stdout del
                # daemon (= log file).
                with _redirect_cli_consoles(self.console):
                    try:
                        self.handlers[prefix](args)
                    except typer.Exit:
                        pass                 # error ya impreso
                    except Exception as exc:  # noqa: BLE001
                        self.console.print(f"[red]Error inesperado:[/red] {exc}")
                return
        self.console.print(
            f"[red]Comando desconocido:[/red] {line!r}. Escribe 'help'."
        )

    # ------------------------------------------------------------------
    # Command handlers
    # ------------------------------------------------------------------

    def _cmd_help(self, args: list[str]) -> None:
        self.console.print(_HELP_TEXT)

    def _cmd_clear(self, args: list[str]) -> None:
        self.console.clear()

    def _cmd_scenario_list(self, args: list[str]) -> None:
        from flexipwn.layer4.cli.scenario import scenario_list
        scenario_list()

    def _cmd_scenario_load(self, args: list[str]) -> None:
        if len(args) != 1:
            self.console.print("[red]Uso:[/red] scenario load <yaml>")
            return
        from flexipwn.layer4.cli.scenario import scenario_load
        scenario_load(args[0])

    def _cmd_scenario_show(self, args: list[str]) -> None:
        if len(args) != 1:
            self.console.print("[red]Uso:[/red] scenario show <id>")
            return
        from flexipwn.layer4.cli.scenario import scenario_show
        scenario_show(args[0])

    @staticmethod
    def _wants_yes(args: list[str]) -> bool:
        return any(a in ("--yes", "-y") for a in args)

    def _cmd_scenario_remove(self, args: list[str]) -> None:
        yes = self._wants_yes(args)
        positional = [a for a in args if not a.startswith("-")]
        if len(positional) != 1:
            self.console.print("[red]Uso:[/red] scenario remove <id> [--yes]")
            return
        from flexipwn.layer4.cli.scenario import _perform_scenario_removal
        _perform_scenario_removal(
            positional[0],
            confirm=lambda msg: yes
            or self._prompter(f"{msg} [y/N] ").strip().lower() in ("y", "yes"),
        )

    def _cmd_scenario_reset_all(self, args: list[str]) -> None:
        # Acción destructiva: confirmación NO saltable (sin --yes).
        from flexipwn.layer4.cli.cleanup import _perform_reset_all
        _perform_reset_all(
            confirm=lambda msg: self._prompter(f"{msg}: ").strip() == "BORRAR",
            mode="scenario",
        )

    def _cmd_participant_add(self, args: list[str]) -> None:
        from flexipwn.layer4.cli.participant import participant_add
        participant_add()

    def _cmd_participant_list(self, args: list[str]) -> None:
        from flexipwn.layer4.cli.participant import participant_list
        participant_list()

    def _cmd_participant_reset_password(self, args: list[str]) -> None:
        if len(args) != 1:
            self.console.print(
                "[red]Uso:[/red] participant reset-password <username>"
            )
            return
        from flexipwn.layer4.cli.participant import participant_reset_password
        participant_reset_password(args[0])

    def _cmd_participant_reset_all(self, args: list[str]) -> None:
        # Acción destructiva: confirmación NO saltable (sin --yes).
        from flexipwn.layer4.cli.cleanup import _perform_reset_all
        _perform_reset_all(
            confirm=lambda msg: self._prompter(f"{msg}: ").strip() == "BORRAR",
            mode="participant",
        )

    def _cmd_participant_remove(self, args: list[str]) -> None:
        if len(args) != 1:
            self.console.print("[red]Uso:[/red] participant remove <username>")
            return
        username = args[0]
        with get_session() as session:
            participant = repository.get_participant_by_username(session, username)
            if participant is None:
                self.console.print(
                    f"[red]Participante no encontrado:[/red] {username!r}"
                )
                return
            active = repository.get_active_runs_by_participant(
                session, participant.id
            )
            if active:
                env_ids = ", ".join(r.env_id for r in active)
                self.console.print(
                    f"[red]El participante {username!r} tiene runs activos:[/red] {env_ids}\n"
                    f"Detén los runs con [yellow]run stop <env_id>[/yellow] antes."
                )
                return
            participant_id = participant.id
        confirm = self._prompter(
            f"¿Eliminar participante {username}? [y/N] "
        ).strip().lower()
        if confirm not in ("y", "yes"):
            self.console.print("[dim]Cancelado.[/dim]")
            return
        with get_session() as session:
            repository.delete_participant(session, participant_id)
        self.console.print(f"[green]Participante {username} eliminado.[/green]")

    def _cmd_run_start(self, args: list[str]) -> None:
        # En el REPL siempre lanzamos el wizard (los flags --scenario/--participant
        # de la CLI siguen disponibles desde fuera del REPL).
        from flexipwn.layer4.cli.run import (
            _print_ssh_instruction,
            _provision_environment,
            _wait_for_credentials,
            DAEMON_CRED_TIMEOUT_SECONDS,
        )

        scenario_id = self._pick_scenario_repl()
        if scenario_id is None:
            return
        participant_id = self._pick_participant_repl()
        if participant_id is None:
            return

        config = FlexiPwnConfig()
        env_id, ssh_port, run_id = _provision_environment(
            scenario_id, participant_id, config
        )
        self.console.print(f"\n[green]Entorno activo:[/green] [bold]{env_id}[/bold]")
        username, password = _wait_for_credentials(run_id, DAEMON_CRED_TIMEOUT_SECONDS)
        if username and password:
            _print_ssh_instruction(config.host, ssh_port, username, password)
        else:
            self.console.print(
                f"[yellow]El daemon no publicó credenciales SSH en "
                f"{DAEMON_CRED_TIMEOUT_SECONDS}s.[/yellow] env_id: {env_id}\n"
                f"Consulta más tarde con [yellow]run show {env_id}[/yellow]."
            )

    def _cmd_run_stop(self, args: list[str]) -> None:
        if len(args) != 1:
            self.console.print("[red]Uso:[/red] run stop <env_id>")
            return
        from flexipwn.layer4.cli.run import run_stop
        run_stop(args[0])

    def _cmd_run_reset(self, args: list[str]) -> None:
        if len(args) != 1:
            self.console.print("[red]Uso:[/red] run reset <env_id>")
            return
        from flexipwn.layer4.cli.run import run_reset
        run_reset(args[0])

    def _cmd_run_remove(self, args: list[str]) -> None:
        if len(args) != 1:
            self.console.print("[red]Uso:[/red] run remove <env_id>")
            return
        from flexipwn.layer4.cli.run import _perform_run_removal
        _perform_run_removal(
            args[0],
            confirm=lambda msg: self._prompter(f"{msg} [y/N] ").strip().lower()
            in ("y", "yes"),
        )

    def _cmd_run_list(self, args: list[str]) -> None:
        from flexipwn.layer4.cli.run import run_list
        run_list(scenario=None, participant=None)

    def _cmd_run_show(self, args: list[str]) -> None:
        if len(args) != 1:
            self.console.print("[red]Uso:[/red] run show <env_id>")
            return
        from flexipwn.layer4.cli.run import run_show
        run_show(args[0])

    def _cmd_run_progress(self, args: list[str]) -> None:
        if len(args) != 1:
            self.console.print("[red]Uso:[/red] run progress <env_id>")
            return
        from flexipwn.layer4.cli.run import run_progress
        run_progress(args[0])

    @staticmethod
    def _wants_all(args: list[str]) -> bool:
        return any(a in ("--all", "all", "-a") for a in args)

    def _cmd_dashboard(self, args: list[str]) -> None:
        from flexipwn.layer4.cli.run import dashboard_view
        dashboard_view(all_runs=self._wants_all(args))

    def _cmd_feed(self, args: list[str]) -> None:
        from flexipwn.layer4.cli.run import feed_view
        feed_view(all_history=self._wants_all(args))

    def _cmd_run_watch(self, args: list[str]) -> None:
        if len(args) != 1:
            self.console.print("[red]Uso:[/red] run watch <env_id>")
            return
        from flexipwn.layer4.cli.run import _print_event
        env_id = args[0]
        with get_session() as session:
            run = repository.get_run_by_env_id(session, env_id)
            if run is None:
                self.console.print(f"[red]Run no encontrado:[/red] {env_id}")
                return
            run_id = run.id
            events = repository.list_run_events(session, run_id)
        self.console.print(
            f"[bold]Watching run:[/bold] {env_id} [dim](Ctrl+C para volver al prompt)[/dim]\n"
        )
        last_ts = None
        for ev in events:
            _print_event(ev)
            last_ts = ev.timestamp
        cancel = _current_cancel_event()
        try:
            while True:
                # Si el cliente attach desconectó, sale limpiamente en vez
                # de orfanar el thread.
                if cancel is not None and cancel.is_set():
                    return
                time.sleep(1)
                with get_session() as session:
                    new_events = repository.list_run_events(
                        session, run_id, since=last_ts
                    )
                for ev in new_events:
                    _print_event(ev)
                    last_ts = ev.timestamp
        except KeyboardInterrupt:
            self.console.print(
                "\n[dim]Watch finalizado (el run sigue activo si está en marcha).[/dim]"
            )

    def _cmd_run_batch_start(self, args: list[str]) -> None:
        if len(args) < 1:
            self.console.print(
                "[red]Uso:[/red] run batch-start <yaml> [--output <csv>]"
            )
            return
        # Parseo simple: primer arg es yaml; soporta --output <csv>.
        yaml_path = args[0]
        output: str | None = None
        if "--output" in args:
            idx = args.index("--output")
            if idx + 1 < len(args):
                output = args[idx + 1]
        from flexipwn.layer4.cli.run import run_batch_start
        run_batch_start(yaml_path, output=output)

    def _cmd_daemon_status(self, args: list[str]) -> None:
        with get_session() as session:
            active = repository.get_runs_needing_action(session)
        self.console.print(
            f"[green]Daemon: corriendo[/green] (REPL foreground in-process)"
        )
        self.console.print(f"Runs activos: {len(active)}")
        for r in active:
            self.console.print(f"  • {r.env_id}  [{r.status}]")

    # ------------------------------------------------------------------
    # Wizard helpers (REPL-native)
    # ------------------------------------------------------------------

    def _pick_scenario_repl(self) -> uuid.UUID | None:
        with get_session() as session:
            scenarios = repository.list_scenarios(session)
        if not scenarios:
            self.console.print(
                "[red]No hay escenarios cargados.[/red] "
                "Carga uno con: [yellow]scenario load <yaml>[/yellow]"
            )
            return None
        table = Table(title="Escenarios disponibles", show_header=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("Título", style="cyan")
        table.add_column("Categoría")
        table.add_column("Nivel")
        for i, s in enumerate(scenarios, 1):
            table.add_row(str(i), s.title, s.category, s.level)
        self.console.print(table)
        raw = self._prompter("Selecciona el número del escenario: ").strip()
        try:
            idx = int(raw)
        except ValueError:
            self.console.print("[red]Selección inválida.[/red]")
            return None
        if idx < 1 or idx > len(scenarios):
            self.console.print("[red]Selección fuera de rango.[/red]")
            return None
        return scenarios[idx - 1].id

    def _pick_participant_repl(self) -> uuid.UUID | None:
        with get_session() as session:
            participants = repository.list_participants(session)
        if not participants:
            self.console.print(
                "[red]No hay participantes.[/red] "
                "Crea uno con: [yellow]participant add[/yellow]"
            )
            return None
        table = Table(title="Participantes", show_header=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("Username", style="cyan")
        table.add_column("Creado")
        for i, p in enumerate(participants, 1):
            table.add_row(str(i), p.username, str(p.created_at)[:19])
        self.console.print(table)
        raw = self._prompter("Selecciona el número del participante: ").strip()
        try:
            idx = int(raw)
        except ValueError:
            self.console.print("[red]Selección inválida.[/red]")
            return None
        if idx < 1 or idx > len(participants):
            self.console.print("[red]Selección fuera de rango.[/red]")
            return None
        return participants[idx - 1].id
