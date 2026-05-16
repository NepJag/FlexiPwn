from flexipwn.layer2.events import MonitorEvent
from flexipwn.layer3.targets.base import TargetEvaluator


class ProcessRunningEvaluator(TargetEvaluator):
    """
    Matchea cuando un nuevo proceso cumple las condiciones del target.

    Solo responde a eventos con event_type == "process_spawned".

    Campos obligatorios:
      euid: int          — effective UID requerido (0 para root)
      cmd_contains: str  — substring que debe estar en cmd del proceso

    Campos opcionales (AND implícito con los anteriores):
      ppid_cmd_contains: str  — substring que debe estar en cmd del padre directo
      ancestor_contains: str  — substring que debe estar en algún ancestro de la cadena
    """

    def matches(self, event: MonitorEvent) -> bool:
        if event.event_type != "process_spawned":
            return False

        details = event.details

        euid_ok = details.get("euid") == self.config.euid
        cmd_ok = self.config.cmd_contains in details.get("cmd", "")

        if not (euid_ok and cmd_ok):
            return False

        if self.config.ppid_cmd_contains is not None:
            ppid_cmd = details.get("ppid_cmd", "")
            if self.config.ppid_cmd_contains not in ppid_cmd:
                return False

        if self.config.ancestor_contains is not None:
            ancestor_cmds = details.get("ancestor_cmds", "")
            ancestor_str = " ".join(ancestor_cmds)
            if self.config.ancestor_contains not in ancestor_str:
                return False

        return True
