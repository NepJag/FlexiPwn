from __future__ import annotations

import json
import logging
import secrets
import signal
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console

from flexipwn.config import FlexiPwnConfig
from flexipwn.layer1.docker_rootless import DockerRootlessProvider
from flexipwn.layer1.provider import (
    Environment,
    EnvironmentNotFoundError,
    ImageNotFoundError,
)
from flexipwn.layer2.events import MonitorEvent
from flexipwn.layer2.filesystem import FilesystemMonitor
from flexipwn.layer2.log import LogMonitor
from flexipwn.layer2.network import NetworkMonitor
from flexipwn.layer2.orchestrator import MonitorOrchestrator
from flexipwn.layer2.process import ProcessMonitor
from flexipwn.layer3.engine import EvaluationEngine, EvaluationResult
from flexipwn.layer3.schema import ScenarioConfig, scenario_requires_network_capture
from flexipwn.layer4.core.port_allocator import find_free_port
from flexipwn.layer4.core.notifications import (
    Notification,
    NotificationKind,
    NotificationSink,
)
from flexipwn.layer4.core.student_status import push_student_status
from flexipwn.layer4.core.super_monitor import RichProgressPrinter, SuperMonitor
from flexipwn.layer4.db import repository
from flexipwn.layer4.db.models import ExerciseRun, Participant
from flexipwn.layer4.db.session import get_session

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(UTC)


def _build_orchestrator(
    scenario_config: ScenarioConfig,
    docker_env: Environment,
    provider: DockerRootlessProvider,
    event_sink,
    on_stopped,
) -> MonitorOrchestrator:
    enable_network_capture = scenario_requires_network_capture(scenario_config)

    host_log_paths: list[str] = []
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


def _setup_attacker_user(
    provider: DockerRootlessProvider,
    env_id: str,
    username: str,
    password: str,
) -> None:
    """Crea el usuario {username} en el contenedor atacante con contraseña SSH."""
    safe_user = username.replace("'", "")
    safe_pw = password.replace("'", "'\\''")
    provider.exec_run(
        env_id, f"useradd -m -s /bin/bash {safe_user}", container="attacker"
    )
    provider.exec_run(
        env_id,
        f"bash -c 'echo \"{safe_user}:{safe_pw}\" | chpasswd'",
        container="attacker",
    )
    # NO sudo: el estudiante trabaja solo con las herramientas pre-instaladas
    # en flexipwn/attacker. Cualquier privesc dentro del contenedor atacante
    # invalida la metodología educativa.


class DaemonLoop:
    """Loop principal del daemon FlexiPwn.

    Mantiene el SuperMonitor vivo y reconcilia el estado de la DB con Docker.
    """

    def __init__(
        self,
        config: FlexiPwnConfig | None = None,
        console: Console | None = None,
    ) -> None:
        self.config = config or FlexiPwnConfig()
        self.console = console or Console()
        self.provider = DockerRootlessProvider(config=self.config)
        self.super_monitor = SuperMonitor(
            poll_interval=self.config.super_monitor_poll_interval,
            max_workers=self.config.super_monitor_max_workers,
        )
        # Sink único para todas las notificaciones del daemon. La política por
        # defecto silencia SSH_READY (no ensucia el TTY) e imprime el progreso.
        self.notifier = NotificationSink(self.console)
        self.printer = RichProgressPrinter(notifier=self.notifier)
        self._stop_event = threading.Event()
        # env_id -> (engine, orchestrator) para no duplicar registros
        self._registered: dict[str, tuple[EvaluationEngine, MonitorOrchestrator]] = {}
        self._registered_lock = threading.Lock()
        self._reconciled = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def install_signal_handlers(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: self._stop_event.set())

    def run(self) -> None:
        self.super_monitor.start()
        self.console.print("[green]Daemon FlexiPwn iniciado.[/green]")
        try:
            while not self._stop_event.is_set():
                try:
                    self._tick()
                except Exception:
                    logger.exception("Error en tick del daemon")
                self._stop_event.wait(timeout=self.config.super_monitor_poll_interval)
        finally:
            self.console.print("[yellow]Deteniendo daemon...[/yellow]")
            self.super_monitor.stop()
            self.console.print("[dim]SuperMonitor detenido. Entornos Docker preservados.[/dim]")

    def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Tick
    # ------------------------------------------------------------------

    def _tick(self) -> None:
        if not self._reconciled:
            self._reconcile()
            self._reconciled = True

        with get_session() as session:
            runs = repository.get_runs_needing_action(session)

        for run in runs:
            try:
                if run.status == "running":
                    self._handle_running(run)
                elif run.status == "stopping":
                    self._handle_stopping(run)
                elif run.status == "resetting":
                    self._handle_resetting(run)
            except Exception as exc:
                logger.exception(
                    "Error procesando run %s (status=%s)", run.env_id, run.status
                )
                with get_session() as session:
                    repository.set_run_status(
                        session, run.id, "failed", message=str(exc)
                    )

    # ------------------------------------------------------------------
    # Reconciliation
    # ------------------------------------------------------------------

    def _reconcile(self) -> None:
        """Intenta retomar runs en estado running cuyos contenedores existan."""
        with get_session() as session:
            runs = list(repository.get_runs_needing_action(session))
            run_snapshots = [
                (
                    r.id,
                    r.env_id,
                    r.status,
                    r.scenario_id,
                    r.participant_id,
                )
                for r in runs
            ]

        for run_id, env_id, status, scenario_id, participant_id in run_snapshots:
            if status != "running":
                continue
            try:
                self.provider.attach_existing(env_id)
            except EnvironmentNotFoundError:
                self.console.print(
                    f"[yellow][{env_id}][/yellow] contenedor faltante; "
                    f"marcando como failed."
                )
                with get_session() as session:
                    repository.set_run_status(
                        session,
                        run_id,
                        "failed",
                        message="Contenedor Docker no existe al reconciliar.",
                    )

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    def _handle_running(self, run: ExerciseRun) -> None:
        env_id = run.env_id
        with self._registered_lock:
            if env_id in self._registered:
                return  # ya registrado

        # Hidratar estado desde DB (Scenario, Participant)
        with get_session() as session:
            scenario = repository.get_scenario(session, run.scenario_id)
            participant = session.get(Participant, run.participant_id)
            if scenario is None or participant is None:
                repository.set_run_status(
                    session, run.id, "failed",
                    message="Scenario o Participant no encontrado.",
                )
                return
            scenario_config = repository.parse_scenario_config(scenario)
            run_id = run.id
            scenario_id = run.scenario_id
            participant_id = run.participant_id
            username = participant.username
            existing_password = run.attacker_ssh_password
            existing_port = run.attacker_ssh_port
            started_at = run.started_at or _now()

        # Hidratar Environment del provider (carga baseline + verifica contenedor)
        try:
            docker_env = self.provider.attach_existing(env_id)
        except EnvironmentNotFoundError as exc:
            with get_session() as session:
                repository.set_run_status(
                    session, run_id, "failed", message=str(exc)
                )
            return

        # Generar credenciales SSH si faltan
        if not existing_password:
            password = secrets.token_urlsafe(12)
            try:
                _setup_attacker_user(self.provider, env_id, username, password)
            except Exception as exc:
                with get_session() as session:
                    repository.set_run_status(
                        session, run_id, "failed",
                        message=f"useradd/chpasswd falló: {exc}",
                    )
                return
            with get_session() as session:
                repository.set_attacker_ssh_credentials(
                    session, run_id, username, password, existing_port or 0
                )
            self.notifier.emit(
                Notification(
                    kind=NotificationKind.SSH_READY,
                    env_id=env_id,
                    message=(
                        f"[green][{env_id}][/green] SSH listo: "
                        f"ssh {username}@{self.config.host} -p {existing_port} "
                        f"(clave: {password})"
                    ),
                )
            )

        engine = EvaluationEngine(
            scenario=scenario_config,
            scenario_id=str(scenario_id),
            participant_id=str(participant_id),
            env_id=env_id,
            on_update=self._build_engine_callback(env_id, run_id, scenario_config),
        )

        def event_sink(event: MonitorEvent, _run_id=run_id, _engine=engine) -> None:
            try:
                with get_session() as s:
                    repository.append_run_event(s, _run_id, event)
            except Exception:
                logger.exception("Error guardando RunEvent en DB")
            _engine.process_event(event)

        def on_stopped(stopped_env_id: str, _run_id=run_id) -> None:
            # Race protection: si el engine ya marcó completed (y disparó
            # destroy), un poll en vuelo detectaría "container gone" y nos
            # llamaría aquí. NO sobreescribir un estado terminal.
            with get_session() as s:
                run = s.get(ExerciseRun, _run_id)
                if run is None or run.status in (
                    "completed", "failed", "timeout", "stopped"
                ):
                    return
                repository.set_run_status(
                    s, _run_id, "stopped",
                    message="Contenedor detenido.",
                )
            self.console.print(
                f"[yellow][{stopped_env_id}][/yellow] contenedor detenido."
            )

        orchestrator = _build_orchestrator(
            scenario_config=scenario_config,
            docker_env=docker_env,
            provider=self.provider,
            event_sink=event_sink,
            on_stopped=on_stopped,
        )

        def on_timeout(env_id_t: str, _run_id=run_id) -> None:
            self.console.print(
                f"[red][{env_id_t}][/red] timeout alcanzado."
            )
            with get_session() as s:
                repository.set_run_status(s, _run_id, "timeout")
            try:
                self.provider.destroy(env_id_t)
            except Exception:
                pass
            with self._registered_lock:
                self._registered.pop(env_id_t, None)

        self.super_monitor.add_environment(
            env_id=env_id,
            orchestrator=orchestrator,
            run_id=run_id,
            started_at=started_at,
            timeout_seconds=scenario_config.timeout_seconds,
            on_timeout=on_timeout,
        )
        with self._registered_lock:
            self._registered[env_id] = (engine, orchestrator)

        # Estado inicial del visor del estudiante en el atacante (hints +
        # objetivos sin cumplir). El callback del engine lo refresca en cada hito.
        push_student_status(self.provider, env_id, scenario_config)

    def _handle_stopping(self, run: ExerciseRun) -> None:
        env_id = run.env_id
        run_id = run.id
        progress = run.progress
        self.super_monitor.remove_environment(env_id)
        with self._registered_lock:
            entry = self._registered.pop(env_id, None)
        if entry:
            try:
                entry[1].stop()
            except Exception:
                pass
        try:
            self.provider.destroy(env_id)
        except Exception as exc:
            logger.warning("destroy %s: %s", env_id, exc)
        final = "completed" if progress >= 1.0 else "stopped"
        with get_session() as session:
            repository.set_run_status(session, run_id, final)
        self.printer.reset(env_id)
        self.console.print(f"[green][{env_id}][/green] entorno destruido ({final}).")

    def _handle_resetting(self, run: ExerciseRun) -> None:
        env_id = run.env_id
        run_id = run.id
        payload_json = run.reset_payload

        # 1. Detener monitoreo y destruir entorno actual
        self.super_monitor.remove_environment(env_id)
        with self._registered_lock:
            entry = self._registered.pop(env_id, None)
        if entry:
            try:
                entry[1].stop()
            except Exception:
                pass
        try:
            self.provider.destroy(env_id)
        except Exception as exc:
            logger.warning("destroy %s: %s", env_id, exc)
        self.printer.reset(env_id)

        # 2. Cargar params del payload
        try:
            payload = json.loads(payload_json) if payload_json else {}
        except Exception:
            payload = {}

        with get_session() as session:
            scenario = repository.get_scenario(session, run.scenario_id)
            participant = session.get(Participant, run.participant_id)
            if scenario is None or participant is None:
                repository.set_run_status(
                    session, run_id, "failed",
                    message="Scenario o Participant ausente al resetear.",
                )
                return
            scenario_config = repository.parse_scenario_config(scenario)
            scenario_id = run.scenario_id
            participant_id = run.participant_id
            username = participant.username

        # 3. Asignar puerto + crear entorno nuevo
        try:
            new_port = find_free_port(
                self.config.attacker_port_range_start,
                self.config.attacker_port_range_end,
            )
        except RuntimeError as exc:
            with get_session() as session:
                repository.set_run_status(session, run_id, "failed",
                                          message=str(exc))
            return

        try:
            new_docker_env = self.provider.create(
                scenario_id=str(scenario_id),
                participant_id=str(participant_id),
                image=payload.get("image", scenario_config.environment.image),
                attacker_image=payload.get(
                    "attacker_image", scenario_config.environment.attacker_image
                ),
                ports=payload.get("ports") or scenario_config.environment.ports or None,
                attacker_ports=[f"{new_port}:22"],
                log_paths=payload.get("log_paths")
                or scenario_config.environment.log_paths
                or None,
                startup_delay=payload.get(
                    "startup_delay_seconds",
                    scenario_config.environment.startup_delay_seconds,
                ),
                enable_network_capture=scenario_requires_network_capture(
                    scenario_config
                ),
                capture_filter=payload.get(
                    "capture_filter", scenario_config.environment.capture_filter
                ),
            )
        except Exception as exc:
            with get_session() as session:
                repository.set_run_status(session, run_id, "failed",
                                          message=f"recreate falló: {exc}")
            return

        # NOTA: provider.create() genera un env_id nuevo (renombrar
        # contenedores/redes preservando el original es no-trivial en rootless).
        # Actualizamos env_id en el ExerciseRun; el run_id (PK) permanece
        # estable, preservando el historial de TargetResults vía reset_at.
        new_env_id = new_docker_env.env_id

        # 4. Generar SSH creds nuevas
        password = secrets.token_urlsafe(12)
        try:
            _setup_attacker_user(self.provider, new_env_id, username, password)
        except Exception as exc:
            with get_session() as session:
                repository.set_run_status(session, run_id, "failed",
                                          message=f"useradd post-reset falló: {exc}")
            return

        # 5. Persistir nuevo estado en DB
        with get_session() as session:
            run_db = session.get(ExerciseRun, run_id)
            if run_db is None:
                return
            run_db.env_id = new_env_id
            run_db.status = "running"
            run_db.progress = 0.0
            run_db.started_at = _now()
            run_db.finished_at = None
            run_db.attacker_ssh_username = username
            run_db.attacker_ssh_password = password
            run_db.attacker_ssh_port = new_port
            run_db.reset_payload = None
            session.add(run_db)
            session.commit()
            repository.bulk_create_target_results(session, run_id, scenario_config)

        self.console.print(
            f"[green][{new_env_id}][/green] reset completado. "
            f"Nueva clave SSH: {password}  Puerto: {new_port}"
        )
        # Visor del estudiante fresco para el entorno recreado (objetivos sin
        # cumplir + hints). El siguiente tick lo re-registra en el SuperMonitor.
        push_student_status(self.provider, new_env_id, scenario_config)

    # ------------------------------------------------------------------
    # Engine callback
    # ------------------------------------------------------------------

    def _build_engine_callback(
        self, env_id: str, run_id: uuid.UUID, scenario_config: ScenarioConfig
    ):
        rich_cb = self.printer.build_callback(env_id)

        def _on_update(result: EvaluationResult) -> None:
            try:
                with get_session() as s:
                    repository.update_run_progress(s, run_id, result.progress)
                    repository.update_target_results_from_engine(s, run_id, result)
            except Exception:
                logger.exception("Error actualizando progreso en DB")
            # Refresca el visor del estudiante en el atacante. Al completar no se
            # actualiza: el entorno se destruye a continuación y el exec fallaría.
            if not result.completed:
                push_student_status(self.provider, env_id, scenario_config, result)
            try:
                rich_cb(result)
            except Exception:
                logger.exception("Error en RichProgressPrinter")
            if result.completed:
                try:
                    with get_session() as s:
                        repository.set_run_status(s, run_id, "completed")
                    self.super_monitor.remove_environment(env_id)
                    with self._registered_lock:
                        self._registered.pop(env_id, None)
                    self.provider.destroy(env_id)
                    # Ya no es un print suelto sobre el prompt: va por el sink
                    # (silenciado) y queda como entrada persistente del feed,
                    # sintetizada desde ExerciseRun.finished_at.
                    self.notifier.emit(
                        Notification(
                            kind=NotificationKind.RUN_COMPLETED,
                            env_id=env_id,
                            message=f"[bold green][{env_id}] ✓ ESCENARIO COMPLETADO[/bold green]",
                        )
                    )
                except Exception:
                    logger.exception("Error finalizando run completado")

        return _on_update
