from __future__ import annotations

import re

from flexipwn.layer2.events import MonitorEvent
from flexipwn.layer3.targets.base import TargetEvaluator


class NetworkPayloadEvaluator(TargetEvaluator):
    """
    Matchea cuando el payload de un paquete de red cumple todas las condiciones
    de field_matches (regex aplicada con re.search sobre details["data"]).

    Solo responde a eventos con event_type == "network_payload".
    Misma semántica que LogPatternEvaluator.
    """

    def matches(self, event: MonitorEvent) -> bool:
        if event.event_type != "network_payload":
            return False
        if not self.config.field_matches:
            return False

        data = event.details.get("data", "")

        for _field, pattern in self.config.field_matches.items():
            try:
                if not re.search(str(pattern), data, re.IGNORECASE):
                    return False
            except re.error:
                return False

        return True


class NetworkConnectionEvaluator(TargetEvaluator):
    """
    Matchea cuando se detecta una conexión TCP establecida hacia un puerto
    (y opcionalmente IP) específico.

    Solo responde a eventos con event_type == "network_connection".

    Campos requeridos en config:
    - dst_port: puerto destino de la conexión (obligatorio)
    - dst_ip: IP destino (opcional — si None, cualquier IP hace match)
    """

    def matches(self, event: MonitorEvent) -> bool:
        if event.event_type != "network_connection":
            return False
        if event.details.get("dst_port") != self.config.dst_port:
            return False
        if self.config.dst_ip is not None:
            if event.details.get("dst_ip") != self.config.dst_ip:
                return False
        return True
