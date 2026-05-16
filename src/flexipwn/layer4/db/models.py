from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import Column, DateTime
from sqlmodel import Field, SQLModel


def _now() -> datetime:
    return datetime.now(UTC)


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


class Scenario(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=_uuid, primary_key=True)
    yaml_path: str
    yaml_content: str
    title: str
    description: str
    author: str
    level: str
    category: str
    image: str
    attacker_image: str | None = None
    timeout_seconds: int = 1800
    created_at: datetime = Field(
        default_factory=_now,
        sa_column=Column(DateTime(timezone=True), nullable=False, default=_now),
    )


class Participant(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=_uuid, primary_key=True)
    username: str = Field(unique=True, index=True)
    password_hash: str
    created_at: datetime = Field(
        default_factory=_now,
        sa_column=Column(DateTime(timezone=True), nullable=False, default=_now),
    )


RunStatus = Literal[
    "pending",
    "running",
    "stopping",
    "resetting",
    "completed",
    "failed",
    "timeout",
    "stopped",
]


class ExerciseRun(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=_uuid, primary_key=True)
    scenario_id: uuid.UUID = Field(foreign_key="scenario.id", index=True)
    participant_id: uuid.UUID = Field(foreign_key="participant.id", index=True)
    env_id: str = Field(unique=True, index=True)
    status: str = "pending"
    progress: float = 0.0
    started_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    finished_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    created_at: datetime = Field(
        default_factory=_now,
        sa_column=Column(DateTime(timezone=True), nullable=False, default=_now),
    )
    attacker_ssh_port: int | None = None
    attacker_ssh_username: str | None = None
    # La contraseña SSH se persiste en plaintext porque la SQLite reside en
    # el servidor del educador, los participantes no tienen acceso al host,
    # y cifrar añade complejidad desproporcionada para el contexto educativo.
    # Si el archivo .db queda expuesto, las credenciales SSH de los
    # contenedores atacantes (entornos efímeros) quedan comprometidas;
    # nunca el host.
    attacker_ssh_password: str | None = None
    reset_payload: str | None = None
    daemon_message: str | None = None


class TargetResult(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=_uuid, primary_key=True)
    run_id: uuid.UUID = Field(foreign_key="exerciserun.id", index=True)
    target_index: int
    target_type: str
    description: str
    matched: bool = False
    matched_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    trigger_event: str | None = None  # JSON serializado de MonitorEvent
    reset_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )


class RunEvent(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=_uuid, primary_key=True)
    run_id: uuid.UUID = Field(foreign_key="exerciserun.id", index=True)
    timestamp: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    monitor_type: str
    event_type: str
    details_json: str
