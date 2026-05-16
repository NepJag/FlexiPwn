from flexipwn.layer3.schema import TargetConfig
from flexipwn.layer3.targets.base import TargetEvaluator
from flexipwn.layer3.targets.filesystem import (
    FileCreatedEvaluator,
    FileExistsEvaluator,
    FileModifiedEvaluator,
)
from flexipwn.layer3.targets.log import LogPatternEvaluator
from flexipwn.layer3.targets.network import NetworkConnectionEvaluator, NetworkPayloadEvaluator
from flexipwn.layer3.targets.process import ProcessRunningEvaluator

_EVALUATORS: dict[str, type[TargetEvaluator]] = {
    "file_created": FileCreatedEvaluator,
    "file_modified": FileModifiedEvaluator,
    "file_exists": FileExistsEvaluator,
    "process_running": ProcessRunningEvaluator,
    "log_pattern": LogPatternEvaluator,
    "network_payload": NetworkPayloadEvaluator,
    "network_connection": NetworkConnectionEvaluator,
}


def get_evaluator(config: TargetConfig) -> TargetEvaluator | None:
    """
    Retorna el evaluador correspondiente al tipo de target.
    Retorna None para nodos lógicos (and/or/not) — se evalúan en el engine.
    Lanza NotImplementedError para tipos hoja aún no implementados.
    """
    if config.type in ("and", "or", "not"):
        return None
    evaluator_cls = _EVALUATORS.get(config.type)
    if evaluator_cls is None:
        raise NotImplementedError(
            f"Evaluador para el tipo '{config.type}' aún no implementado"
        )
    return evaluator_cls(config)
