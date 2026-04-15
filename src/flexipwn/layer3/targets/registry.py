from flexipwn.layer3.schema import TargetConfig
from flexipwn.layer3.targets.base import TargetEvaluator
from flexipwn.layer3.targets.filesystem import (
    FileCreatedEvaluator,
    FileExistsEvaluator,
    FileModifiedEvaluator,
)
from flexipwn.layer3.targets.process import ProcessRunningEvaluator

_EVALUATORS: dict[str, type[TargetEvaluator]] = {
    "file_created": FileCreatedEvaluator,
    "file_modified": FileModifiedEvaluator,
    "file_exists": FileExistsEvaluator,
    "process_running": ProcessRunningEvaluator,
}


def get_evaluator(config: TargetConfig) -> TargetEvaluator:
    """
    Retorna el evaluador correspondiente al tipo de target.
    Lanza NotImplementedError para tipos aún no implementados.
    """
    evaluator_cls = _EVALUATORS.get(config.type)
    if evaluator_cls is None:
        raise NotImplementedError(
            f"Evaluador para el tipo '{config.type}' aún no implementado"
        )
    return evaluator_cls(config)
