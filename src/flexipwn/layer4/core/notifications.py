from __future__ import annotations

import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

from rich.console import Console

logger = logging.getLogger(__name__)


class NotificationKind(str, Enum):
    """Tipos de notificación que el daemon emite hacia el educador."""

    SSH_READY = "ssh_ready"
    TARGET_MATCHED = "target_matched"
    PROGRESS = "progress"


class NotificationPolicy(str, Enum):
    """Qué hace el sink con una notificación de un tipo dado."""

    PRINT = "print"      # se escribe al TTY compartido (console)
    SILENCE = "silence"  # no toca el TTY; solo log + buffer


@dataclass(frozen=True)
class Notification:
    """Una notificación originada en el daemon.

    `message` ya viene formateado con markup Rich; el sink decide si lo
    imprime al TTY o lo guarda silenciosamente.
    """

    kind: NotificationKind
    env_id: str
    message: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


# Política por defecto.
# El "SSH listo" no ensucia el TTY compartido del educador; la
# credencial igual queda en la tabla final del batch, en `run show` y en log.
_DEFAULT_POLICY: dict[NotificationKind, NotificationPolicy] = {
    NotificationKind.SSH_READY: NotificationPolicy.SILENCE,
    NotificationKind.TARGET_MATCHED: NotificationPolicy.PRINT,
    NotificationKind.PROGRESS: NotificationPolicy.PRINT,
}


class NotificationSink:
    """Punto único por el que pasan todas las notificaciones del daemon.

    Hoy decide, por tipo, si una notificación se imprime al TTY compartido o
    se silencia (queda solo en log). Además conserva las últimas N en un
    buffer en memoria: esa es la base sobre la que se puede construir un feed
    que el educador abra con un comando, sin volver a tocar los puntos de
    emisión (daemon_loop, RichProgressPrinter).
    """

    def __init__(
        self,
        console: Console | None = None,
        *,
        policy: dict[NotificationKind, NotificationPolicy] | None = None,
        buffer_size: int = 500,
    ) -> None:
        self._console = console or Console()
        self._policy: dict[NotificationKind, NotificationPolicy] = dict(_DEFAULT_POLICY)
        if policy:
            self._policy.update(policy)
        self._buffer: deque[Notification] = deque(maxlen=buffer_size)
        self._lock = threading.Lock()

    def emit(self, notification: Notification) -> None:
        """Registra la notificación en el buffer y la imprime o silencia
        según la política de su tipo."""
        with self._lock:
            self._buffer.append(notification)
            policy = self._policy.get(notification.kind, NotificationPolicy.PRINT)

        if policy is NotificationPolicy.PRINT:
            self._console.print(notification.message)
        else:
            logger.info(
                "[%s] %s: %s",
                notification.env_id,
                notification.kind.value,
                notification.message,
            )

    def set_policy(
        self, kind: NotificationKind, policy: NotificationPolicy
    ) -> None:
        """Cambia en caliente qué se hace con un tipo de notificación
        (útil para un futuro `notify level` o `--quiet`)."""
        with self._lock:
            self._policy[kind] = policy

    def recent(self, limit: int | None = None) -> list[Notification]:
        """Devuelve las notificaciones más recientes (base del feed)."""
        with self._lock:
            items = list(self._buffer)
        return items[-limit:] if limit else items

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()
