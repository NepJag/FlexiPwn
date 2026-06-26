"""Configuración centralizada del logging de FlexiPwn (modo verboso).

Un único punto para activar logs DEBUG que recorren todo el flujo: creación de
recursos en Capa 1 (redes, contenedores, sniffer, baseline), emisión de cada
MonitorEvent en Capa 2, decisión de match del engine en Capa 3 y escrituras a la
DB en Capa 4.

Nivel resuelto por precedencia:
  1. argumento ``verbose=True``  → DEBUG
  2. variable de entorno ``FLEXIPWN_LOG`` (DEBUG/INFO/WARNING/ERROR/CRITICAL)
  3. WARNING por defecto (silencioso, comportamiento histórico)

Solo se invoca desde los entrypoints de la CLI (``flexipwn --verbose ...`` y
``flexipwn daemon start --verbose``); importar este módulo no tiene efectos
secundarios, así que los tests que instancian clases directamente no se ven
afectados.
"""

from __future__ import annotations

import logging
import os
import sys

# Logger raíz de la app. Todos los módulos usan getLogger(__name__), que cuelga
# de "flexipwn.*" y hereda nivel y handler de este logger.
_ROOT_NAME = "flexipwn"
_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}

_configured = False


def _resolve_level(verbose: bool) -> int:
    if verbose:
        return logging.DEBUG
    env = os.environ.get("FLEXIPWN_LOG", "").strip().upper()
    if env in _LEVELS:
        return getattr(logging, env)
    return logging.WARNING


def configure_logging(verbose: bool = False) -> int:
    """Configura (idempotentemente) el logging de FlexiPwn y devuelve el nivel.

    ``verbose=False`` no fuerza WARNING: deja que ``FLEXIPWN_LOG`` decida y, si no
    está, cae a WARNING. Así un ``--verbose`` ausente no pisa la variable de
    entorno.
    """
    global _configured
    level = _resolve_level(verbose)
    root = logging.getLogger(_ROOT_NAME)
    root.setLevel(level)

    if not _configured:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
                datefmt="%H:%M:%S",
            )
        )
        root.addHandler(handler)
        # Evita doble emisión si el root global de Python tuviera handlers.
        root.propagate = False
        _configured = True
    else:
        for h in root.handlers:
            h.setLevel(level)

    return level
