from __future__ import annotations

import os
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine, text

from flexipwn.layer4.db import models as _models  # noqa: F401 — registers SQLModel tables


def _resolve_db_path(db_path: str | None = None) -> str:
    if db_path:
        return db_path
    env = os.environ.get("FLEXIPWN_DB_PATH")
    if env:
        return env
    default = Path.home() / ".flexipwn" / "flexipwn.db"
    default.parent.mkdir(parents=True, exist_ok=True)
    return str(default)


_engine = None


def get_engine(db_path: str | None = None):
    global _engine, _engine_path
    if _engine is None:
        resolved = _resolve_db_path(db_path)
        Path(resolved).parent.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(f"sqlite:///{resolved}", echo=False)
        _engine_path = resolved
    return _engine


_engine_path: str | None = None


def init_db(engine=None) -> None:
    if engine is None:
        engine = get_engine()
    SQLModel.metadata.create_all(engine)
    with engine.connect() as conn:
        conn.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_active_run "
            "ON exerciserun(scenario_id, participant_id) WHERE status = 'running'"
        ))
        conn.commit()
    if _engine_path and Path(_engine_path).exists():
        try:
            os.chmod(_engine_path, 0o600)
        except OSError:
            pass


@contextmanager
def get_session(engine=None) -> Generator[Session, None, None]:
    if engine is None:
        engine = get_engine()
    with Session(engine) as session:
        yield session
