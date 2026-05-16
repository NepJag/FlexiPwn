from __future__ import annotations

import re

from flexipwn.layer2.events import MonitorEvent
from flexipwn.layer3.schema import TargetConfig
from flexipwn.layer3.targets.base import TargetEvaluator


class LogPatternEvaluator(TargetEvaluator):
    """
    Matchea cuando una entrada de log cumple todas las condiciones
    definidas en field_matches.

    Solo responde a eventos con event_type == "log_entry".

    Lógica de matching (siempre regex):
    - Cada valor en field_matches se trata como una regex de Python.
    - re.search() busca el patrón en cualquier parte del valor del campo.
    - Strings literales funcionan sin sintaxis especial.
    - Todas las condiciones en field_matches deben cumplirse (AND implícito).

    Campos especiales:
    - "raw_line": se aplica sobre details["raw_line"] (logs de texto plano)
    - Cualquier otro campo: se aplica sobre details["parsed"][campo]
      (logs JSON)

    Si un campo especificado en field_matches no existe en el evento,
    no matchea (no lanza error).
    """

    def matches(self, event: MonitorEvent) -> bool:
        if event.event_type != "log_entry":
            return False
        if not self.config.field_matches:
            return False

        details = event.details

        for field, pattern in self.config.field_matches.items():
            if field == "raw_line":
                value = details.get("raw_line")
            else:
                parsed = details.get("parsed", {})
                value = parsed.get(field) if isinstance(parsed, dict) else None

            if value is None:
                return False

            try:
                if not re.search(str(pattern), str(value)):
                    return False
            except re.error:
                # Pattern inválido: no matchea
                return False

        return True
