from abc import ABC, abstractmethod

from flexipwn.layer2.events import MonitorEvent
from flexipwn.layer3.schema import TargetConfig


class TargetEvaluator(ABC):
    def __init__(self, config: TargetConfig) -> None:
        self.config = config

    @abstractmethod
    def matches(self, event: MonitorEvent) -> bool:
        """
        Retorna True si el evento satisface este target.
        Puro — sin side effects, sin I/O.
        """
        ...
