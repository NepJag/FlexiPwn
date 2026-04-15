from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel


class MonitorEvent(BaseModel):
    timestamp: datetime
    monitor_type: Literal["filesystem", "process", "log"]
    event_type: str
    env_id: str
    participant_id: str
    scenario_id: str
    details: dict[str, Any]
