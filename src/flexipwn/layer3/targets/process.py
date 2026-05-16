from flexipwn.layer2.events import MonitorEvent
from flexipwn.layer3.targets.base import TargetEvaluator


class ProcessRunningEvaluator(TargetEvaluator):
    """
    Matchea cuando un nuevo proceso cumple las condiciones del target.

    Solo responde a eventos con event_type == "process_spawned".

    Campos del target usados:
      euid: int          — effective UID requerido (0 para root)
      cmd_contains: str  — substring que debe estar en cmd del proceso

    Ambos campos son requeridos (validado en schema.py).
    El filtro es AND: euid Y cmd_contains deben cumplirse.
    """

    def matches(self, event: MonitorEvent) -> bool:
        if event.event_type != "process_spawned":
            return False
        details = event.details
        euid_ok = details.get("euid") == self.config.euid
        cmd_ok = self.config.cmd_contains in details.get("cmd", "")
        return euid_ok and cmd_ok
