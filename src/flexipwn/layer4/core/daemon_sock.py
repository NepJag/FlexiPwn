"""Socket Unix para el modo `flexipwn daemon start --detach`.

Permite que `flexipwn daemon attach` abra un REPL contra el daemon en background.

Protocolo de líneas (`\n`-delimited, UTF-8):

  client → server:
    CMD <command line>            ← invoca un comando del REPL
    INPUT <text>                  ← respuesta a un PROMPT pendiente
    BYE                           ← cierra la conexión

  server → client:
    OUT <text con ANSI>           ← una línea de salida (comando o evento del daemon)
    PROMPT <texto>                ← solicita input interactivo (wizard)
    END                           ← el comando terminó (volver al prompt)

Eventos del DaemonLoop (timeouts, SSH ready, target ✓, reset listo) se
broadcastean a TODOS los clientes attached vía `BroadcastFile`. El log file
sigue recibiendo todo (es la base del broadcast).
"""
from __future__ import annotations

import logging
import os
import queue
import socket
import socketserver
import sys
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import IO

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.patch_stdout import patch_stdout
from rich.console import Console

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Broadcast: fan-out de la salida del DaemonLoop al log + clientes attached.
# ---------------------------------------------------------------------------


class BroadcastFile:
    """File-like que escribe a un sink base (log) y replica a N suscriptores.

    El daemon en --detach instancia esto envolviendo `sys.stdout` (= daemon.log
    por el redirect del subprocess), y se lo pasa al `Console` del DaemonLoop.
    Cada cliente attached registra un writer adicional (típicamente un
    `_LinePrefixWriter` que prefija con `OUT ` y envía por su socket).
    """

    def __init__(self, base: IO[str]) -> None:
        self._base = base
        self._subscribers: list[Callable[[str], None]] = []
        self._lock = threading.Lock()

    def subscribe(self, write_fn: Callable[[str], None]) -> Callable[[str], None]:
        with self._lock:
            self._subscribers.append(write_fn)
        return write_fn

    def unsubscribe(self, write_fn: Callable[[str], None]) -> None:
        with self._lock:
            try:
                self._subscribers.remove(write_fn)
            except ValueError:
                pass

    def write(self, data: str) -> int:
        try:
            self._base.write(data)
            self._base.flush()
        except Exception:  # noqa: BLE001
            pass
        # Snapshot para evitar tener el lock durante I/O del cliente.
        with self._lock:
            subs = list(self._subscribers)
        for fn in subs:
            try:
                fn(data)
            except Exception:  # noqa: BLE001
                # Cliente caído; el unsubscribe lo limpiará en su finally.
                pass
        return len(data)

    def flush(self) -> None:
        try:
            self._base.flush()
        except Exception:  # noqa: BLE001
            pass

    def isatty(self) -> bool:
        return False


class _LinePrefixWriter:
    """File-like que prefija cada línea completa con `OUT ` y la envía."""

    def __init__(self, sender: Callable[[str], None], prefix: str = "OUT ") -> None:
        self._sender = sender
        self._prefix = prefix
        self._buf = ""
        self._lock = threading.Lock()

    def write(self, data: str) -> int:
        with self._lock:
            self._buf += data
            while "\n" in self._buf:
                line, self._buf = self._buf.split("\n", 1)
                self._sender(f"{self._prefix}{line}\n")
        return len(data)

    def flush(self) -> None:
        with self._lock:
            if self._buf:
                self._sender(f"{self._prefix}{self._buf}\n")
                self._buf = ""

    def isatty(self) -> bool:
        return False


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


class _Handler(socketserver.StreamRequestHandler):
    """Una conexión = una sesión REPL aislada + suscripción al broadcast."""

    server: "DaemonSocketServer"  # type: ignore[assignment]

    def handle(self) -> None:  # noqa: C901
        from flexipwn.layer4.core.repl import FlexiPwnREPL

        # Estado compartido entre reader thread y executor (este thread).
        input_lock = threading.Lock()
        input_event = threading.Event()
        input_holder: list[str] = []
        cmd_queue: "queue.Queue[str | None]" = queue.Queue()
        closed = threading.Event()

        def reader_loop() -> None:
            """Lee del socket y demultiplexa: INPUT → input_holder, CMD → queue."""
            try:
                for raw in self.rfile:
                    if closed.is_set():
                        break
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    if not line:
                        continue
                    if line.startswith("INPUT "):
                        with input_lock:
                            input_holder.append(line[len("INPUT "):])
                        input_event.set()
                    elif line == "BYE":
                        cmd_queue.put(None)
                        return
                    elif line.startswith("CMD "):
                        cmd_queue.put(line[len("CMD "):].strip())
                    else:
                        logger.debug("attach proto unknown: %r", line)
            except (OSError, ValueError):
                pass
            finally:
                cmd_queue.put(None)
                input_event.set()

        reader_thread = threading.Thread(
            target=reader_loop, daemon=True, name="attach-reader"
        )
        reader_thread.start()

        def _socket_prompter(text: str) -> str:
            self._send(f"PROMPT {text}")
            input_event.clear()
            input_event.wait()
            with input_lock:
                if not input_holder:
                    raise EOFError("client closed during prompt")
                return input_holder.pop(0)

        # Console por-conexión para la salida de comandos del cliente.
        socket_console = Console(
            file=_LinePrefixWriter(self._raw_send),
            force_terminal=True,
            color_system="truecolor",
            width=120,
        )

        # Suscribe esta conexión al broadcast del daemon (eventos del loop).
        broadcast_writer = _LinePrefixWriter(self._raw_send)
        broadcast = self.server.broadcast
        if broadcast is not None:
            broadcast.subscribe(broadcast_writer.write)

        repl = FlexiPwnREPL(
            loop=self.server.loop,
            console=socket_console,
            history_path=Path(os.devnull),
            stop_loop_on_exit=False,
            prompter=_socket_prompter,
        )

        # Anuncio inicial.
        socket_console.print(
            "[green]Conectado al daemon FlexiPwn.[/green] "
            "Escribe 'help' para ver comandos. 'exit' cierra solo este attach."
        )
        self._send("END")

        from flexipwn.layer4.core.repl import use_cancel_event

        try:
            while True:
                cmd = cmd_queue.get()
                if cmd is None:
                    break
                if cmd in ("exit", "quit"):
                    break
                try:
                    # Expone `closed` al handler para que comandos largos
                    # (run watch) puedan terminar al desconectar el cliente.
                    with use_cancel_event(closed):
                        repl.dispatch_line(cmd)
                except Exception:  # noqa: BLE001
                    logger.exception("error sirviendo comando %r", cmd)
                    self._send("OUT [server] error inesperado")
                try:
                    self._send("END")
                except ConnectionError:
                    break
        finally:
            closed.set()
            if broadcast is not None:
                broadcast.unsubscribe(broadcast_writer.write)
            try:
                self._send("OUT [server] sesión cerrada")
            except Exception:  # noqa: BLE001
                pass

    # -- helpers --

    def _send(self, line: str) -> None:
        self._raw_send(line + "\n")

    def _raw_send(self, data: str) -> None:
        try:
            self.wfile.write(data.encode("utf-8", errors="replace"))
            self.wfile.flush()
        except (OSError, ValueError):
            raise ConnectionError("client gone") from None


class _ThreadingUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


class DaemonSocketServer:
    """Socket Unix de control para el daemon en --detach."""

    def __init__(
        self,
        sock_path: Path,
        loop,
        broadcast: BroadcastFile | None = None,
    ) -> None:
        self.sock_path = sock_path
        self.loop = loop
        self.broadcast = broadcast
        self._server: _ThreadingUnixServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self.sock_path.exists():
            try:
                self.sock_path.unlink()
            except OSError:
                pass
        self._server = _ThreadingUnixServer(str(self.sock_path), _Handler)
        self._server.loop = self.loop  # type: ignore[attr-defined]
        self._server.broadcast = self.broadcast  # type: ignore[attr-defined]
        os.chmod(self.sock_path, 0o600)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="daemon-sock",
        )
        self._thread.start()
        logger.info("DaemonSocketServer escuchando en %s", self.sock_path)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self.sock_path.exists():
            try:
                self.sock_path.unlink()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


def attach_client(sock_path: Path) -> None:
    """REPL del cliente: conecta al socket y dialoga con el server.

    Diseño: un thread reader siempre lee del socket y demultiplexa:
      - OUT  → escribe a sys.stdout (bajo patch_stdout aparece sobre el prompt)
      - PROMPT → encola para que el thread principal lo pregunte al usuario
      - END  → señala que el comando actual terminó

    El thread principal maneja prompt_toolkit y serializa los PROMPTs del wizard.
    """
    from flexipwn.layer4.core.repl import (
        build_repl_completer,
        feed_badge_text,
        is_feed_command,
    )

    history_path = Path.home() / ".flexipwn" / "history"
    history_path.parent.mkdir(parents=True, exist_ok=True)
    session: PromptSession[str] = PromptSession(
        history=FileHistory(str(history_path)),
        completer=build_repl_completer(),
        complete_while_typing=False,
    )
    # Cursor de "última lectura" del feed, local a este cliente attach (en
    # memoria, no destructivo). El badge lee la DB directamente: el cliente
    # corre en el mismo host que el daemon y abre el mismo SQLite.
    feed_cursor: list[datetime] = [datetime.now(UTC)]

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(str(sock_path))
    rfile = sock.makefile("r", encoding="utf-8", errors="replace")
    wfile = sock.makefile("w", encoding="utf-8", errors="replace")
    write_lock = threading.Lock()

    def _send(line: str) -> None:
        with write_lock:
            wfile.write(line + "\n")
            wfile.flush()

    end_event = threading.Event()
    eof_event = threading.Event()
    prompt_queue: "queue.Queue[str]" = queue.Queue()

    def reader() -> None:
        try:
            for raw in rfile:
                line = raw.rstrip("\n")
                if line == "END":
                    end_event.set()
                elif line.startswith("OUT "):
                    sys.stdout.write(line[len("OUT "):] + "\n")
                    sys.stdout.flush()
                elif line.startswith("PROMPT "):
                    prompt_queue.put(line[len("PROMPT "):])
                else:
                    sys.stdout.write(f"[proto] {line}\n")
                    sys.stdout.flush()
        except (OSError, ValueError):
            pass
        finally:
            eof_event.set()
            end_event.set()      # desbloquea cualquier wait pendiente

    reader_thread = threading.Thread(target=reader, daemon=True, name="attach-recv")
    reader_thread.start()

    def _handle_pending_prompts() -> None:
        """Procesa todos los PROMPTs pendientes preguntando al usuario."""
        while True:
            try:
                prompt_text = prompt_queue.get_nowait()
            except queue.Empty:
                return
            try:
                response = session.prompt(prompt_text)
            except (KeyboardInterrupt, EOFError):
                response = ""
            _send(f"INPUT {response}")

    try:
        with patch_stdout(raw=True):
            # Espera el END inicial (banner del server).
            end_event.wait(timeout=2.0)
            end_event.clear()

            while not eof_event.is_set():
                try:
                    text = session.prompt(
                        "flexipwn> ",
                        bottom_toolbar=lambda: feed_badge_text(feed_cursor[0]),
                        refresh_interval=2.0,
                    )
                except KeyboardInterrupt:
                    continue
                except EOFError:
                    break
                stripped = text.strip()
                if not stripped:
                    continue
                if stripped in ("exit", "quit"):
                    break

                end_event.clear()
                _send(f"CMD {stripped}")

                # Espera END procesando PROMPTs en el camino.
                while not end_event.is_set() and not eof_event.is_set():
                    if not prompt_queue.empty():
                        _handle_pending_prompts()
                    else:
                        end_event.wait(timeout=0.05)
                # Drain final por si llegó un PROMPT en la última ventana.
                _handle_pending_prompts()
                # Abrir el feed marca lo previo como leído (cursor local).
                if is_feed_command(stripped):
                    feed_cursor[0] = datetime.now(UTC)

            if eof_event.is_set():
                print("[attach] el daemon cerró la conexión.")
    finally:
        try:
            _send("BYE")
        except Exception:  # noqa: BLE001
            pass
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
