import threading
from collections.abc import Callable
from datetime import datetime, timezone

from pydantic import BaseModel

from flexipwn.layer2.events import MonitorEvent
from flexipwn.layer3.schema import ScenarioConfig, TargetConfig
from flexipwn.layer3.targets.base import TargetEvaluator
from flexipwn.layer3.targets.registry import get_evaluator


class TargetResult(BaseModel):
    target_index: int          # posición en la lista targets del YAML
    target_type: str
    description: str
    matched: bool = False
    matched_at: datetime | None = None
    trigger_event: MonitorEvent | None = None


class EvaluationResult(BaseModel):
    scenario_id: str
    participant_id: str
    env_id: str
    condition: str             # "any" | "all"
    targets: list[TargetResult]
    completed: bool
    completed_at: datetime | None = None
    progress: float            # matched / total


EvaluationCallback = Callable[[EvaluationResult], None]


class EvaluationEngine:
    """
    Recibe MonitorEvents y evalúa las condiciones de éxito del escenario.

    Principios:
    - Una vez que un target se marca como matched, no vuelve a False.
    - El callback on_update se invoca SOLO cuando hay un cambio de estado.
    - Engine no accede a Docker ni al filesystem — es pura lógica.
    - Thread-safe: el estado interno está protegido por un Lock.
    """

    def __init__(
        self,
        scenario: ScenarioConfig,
        scenario_id: str,
        participant_id: str,
        env_id: str,
        on_update: EvaluationCallback,
    ) -> None:
        self._scenario = scenario
        self._scenario_id = scenario_id
        self._participant_id = participant_id
        self._env_id = env_id
        self._on_update = on_update
        self._lock = threading.Lock()
        self._evaluators: list[TargetEvaluator] = [
            get_evaluator(t) for t in scenario.targets
        ]
        self._results: list[TargetResult] = self._build_initial_results()

    # ------------------------------------------------------------------
    # Interfaz pública
    # ------------------------------------------------------------------

    def process_event(self, event: MonitorEvent) -> None:
        """
        Procesa un evento. Si algún target nuevo matchea, actualiza el estado
        interno y llama a on_update con el EvaluationResult actualizado.
        Si ningún target cambia, no llama al callback.
        """
        changed = False
        with self._lock:
            for i, (evaluator, result) in enumerate(
                zip(self._evaluators, self._results)
            ):
                if result.matched:
                    continue  # los logros no se revierten
                if evaluator.matches(event):
                    self._results[i] = result.model_copy(update={
                        "matched": True,
                        "matched_at": datetime.now(tz=timezone.utc),
                        "trigger_event": event,
                    })
                    changed = True

            if changed:
                snapshot = self._build_result()

        if changed:
            self._on_update(snapshot)

    def current_result(self) -> EvaluationResult:
        """Retorna el estado actual sin modificarlo."""
        with self._lock:
            return self._build_result()

    def reset(self) -> None:
        """Reinicia todos los targets a matched=False. Para uso en reset del run."""
        with self._lock:
            self._results = self._build_initial_results()

    # ------------------------------------------------------------------
    # Métodos internos
    # ------------------------------------------------------------------

    def _evaluate_condition(self) -> bool:
        """Evalúa any/all sobre el conjunto actual de targets matcheados."""
        matched_flags = [r.matched for r in self._results]
        if self._scenario.condition == "any":
            return any(matched_flags)
        return all(matched_flags)

    def _calculate_progress(self) -> float:
        """len(matched) / len(total_targets)"""
        total = len(self._results)
        if total == 0:
            return 0.0
        matched = sum(1 for r in self._results if r.matched)
        return matched / total

    def _build_initial_results(self) -> list[TargetResult]:
        return [
            TargetResult(
                target_index=i,
                target_type=target.type,
                description=target.description,
            )
            for i, target in enumerate(self._scenario.targets)
        ]

    def _build_result(self) -> EvaluationResult:
        """Construye un EvaluationResult desde el estado actual (debe llamarse con lock)."""
        completed = self._evaluate_condition()
        progress = self._calculate_progress()
        completed_at: datetime | None = None
        if completed:
            # Usar el matched_at más reciente del target que cerró la condición
            matched_times = [r.matched_at for r in self._results if r.matched_at]
            if matched_times:
                completed_at = max(matched_times)
        return EvaluationResult(
            scenario_id=self._scenario_id,
            participant_id=self._participant_id,
            env_id=self._env_id,
            condition=self._scenario.condition,
            targets=list(self._results),
            completed=completed,
            completed_at=completed_at,
            progress=progress,
        )
