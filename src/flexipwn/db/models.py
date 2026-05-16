from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal

from sqlmodel import Field, SQLModel


def _now() -> datetime:
    return datetime.now(timezone.utc)


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
    created_at: datetime = Field(default_factory=_now)


class Participant(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=_uuid, primary_key=True)
    username: str = Field(unique=True, index=True)
    password_hash: str
    created_at: datetime = Field(default_factory=_now)


RunStatus = Literal["pending", "running", "completed", "failed", "timeout", "stopped"]


class ExerciseRun(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=_uuid, primary_key=True)
    scenario_id: uuid.UUID = Field(foreign_key="scenario.id", index=True)
    participant_id: uuid.UUID = Field(foreign_key="participant.id", index=True)
    env_id: str = Field(unique=True, index=True)
    status: str = "pending"
    progress: float = 0.0
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime = Field(default_factory=_now)


class TargetResult(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=_uuid, primary_key=True)
    run_id: uuid.UUID = Field(foreign_key="exerciserun.id", index=True)
    target_index: int
    target_type: str
    description: str
    matched: bool = False
    matched_at: datetime | None = None
    trigger_event: str | None = None  # JSON serializado de MonitorEvent
    reset_at: datetime | None = None


class RunEvent(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=_uuid, primary_key=True)
    run_id: uuid.UUID = Field(foreign_key="exerciserun.id", index=True)
    timestamp: datetime
    monitor_type: str
    event_type: str
    details_json: str
