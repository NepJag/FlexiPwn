import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pydantic import BaseModel

from flexipwn.layer2.events import MonitorEvent
from flexipwn.layer3.schema import ScenarioConfig, TargetConfig
from flexipwn.layer3.targets.base import TargetEvaluator
from flexipwn.layer3.targets.registry import get_evaluator


class TargetResult(BaseModel):
    target_index: int
    target_type: str
    description: str
    matched: bool = False
    matched_at: datetime | None = None
    trigger_event: MonitorEvent | None = None
    children: list["TargetResult"] | None = None  # poblado para nodos lógicos


TargetResult.model_rebuild()


class EvaluationResult(BaseModel):
    scenario_id: str
    participant_id: str
    env_id: str
    condition: str             # "any" | "all"
    targets: list[TargetResult]
    completed: bool
    completed_at: datetime | None = None
    progress: float            # hojas matcheadas / total hojas


EvaluationCallback = Callable[[EvaluationResult], None]


@dataclass
class TargetState:
    index: int
    config: TargetConfig
    matched: bool = False
    matched_at: datetime | None = None
    trigger_event: MonitorEvent | None = None
    children: list["TargetState"] | None = None  # None para hojas
    evaluator: TargetEvaluator | None = None      # None para nodos lógicos


class EvaluationEngine:
    """
    Recibe MonitorEvents y evalúa las condiciones de éxito del escenario.

    Principios:
    - Hojas: una vez matched=True, no vuelve a False.
    - Nodos lógicos (and/or/not): se recalculan en cada cambio.
      El nodo 'not' empieza como matched=True y puede revertir a False.
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
        self._states: list[TargetState] = self._init_states(scenario.targets)

    # ------------------------------------------------------------------
    # Interfaz pública
    # ------------------------------------------------------------------

    def process_event(self, event: MonitorEvent) -> None:
        """
        Procesa un evento. Si algún target nuevo matchea (o un nodo lógico
        cambia de estado), actualiza el estado interno y llama a on_update.
        Si ningún estado cambia, no llama al callback.
        """
        snapshot = None
        with self._lock:
            changed = self._evaluate_leaves(self._states, event)
            if changed:
                self._propagate_logical_nodes(self._states)
                snapshot = self._build_result()

        if snapshot is not None:
            self._on_update(snapshot)

    def current_result(self) -> EvaluationResult:
        with self._lock:
            return self._build_result()

    def reset(self) -> None:
        with self._lock:
            self._reset_states(self._states)

    # ------------------------------------------------------------------
    # Inicialización del árbol
    # ------------------------------------------------------------------

    def _init_states(self, targets: list[TargetConfig]) -> list[TargetState]:
        states = []
        for i, target in enumerate(targets):
            if target.type in ("and", "or", "not"):
                children = self._init_states(target.targets or [])
                # Calcular estado inicial del nodo lógico.
                # 'not' empieza como True porque su hijo aún no ha matcheado.
                if target.type == "and":
                    initial = all(c.matched for c in children)
                elif target.type == "or":
                    initial = any(c.matched for c in children)
                else:  # "not"
                    initial = not children[0].matched
                states.append(TargetState(
                    index=i,
                    config=target,
                    matched=initial,
                    children=children,
                    evaluator=None,
                ))
            else:
                states.append(TargetState(
                    index=i,
                    config=target,
                    children=None,
                    evaluator=get_evaluator(target),
                ))
        return states

    # ------------------------------------------------------------------
    # Evaluación de hojas
    # ------------------------------------------------------------------

    def _evaluate_leaves(
        self, states: list[TargetState], event: MonitorEvent
    ) -> bool:
        """Evalúa todos los nodos hoja. Retorna True si algo cambió."""
        changed = False
        for state in states:
            if state.children is not None:
                if self._evaluate_leaves(state.children, event):
                    changed = True
            else:
                if not state.matched and state.evaluator is not None:
                    if state.evaluator.matches(event):
                        state.matched = True
                        state.matched_at = event.timestamp
                        state.trigger_event = event
                        changed = True
        return changed

    # ------------------------------------------------------------------
    # Propagación de nodos lógicos
    # ------------------------------------------------------------------

    def _propagate_logical_nodes(self, states: list[TargetState]) -> None:
        """
        Recalcula el estado de los nodos lógicos de abajo hacia arriba.
        Debe llamarse después de _evaluate_leaves.
        """
        for state in states:
            if state.children is None:
                continue
            # Propagar hijos primero (bottom-up)
            self._propagate_logical_nodes(state.children)

            old_matched = state.matched
            if state.config.type == "and":
                state.matched = all(c.matched for c in state.children)
            elif state.config.type == "or":
                state.matched = any(c.matched for c in state.children)
            elif state.config.type == "not":
                state.matched = not state.children[0].matched

            if state.matched and not old_matched:
                state.matched_at = datetime.now(timezone.utc)
                matched_children = [c for c in state.children if c.matched]
                if matched_children:
                    state.trigger_event = matched_children[-1].trigger_event

    # ------------------------------------------------------------------
    # Construcción de resultados
    # ------------------------------------------------------------------

    def _build_result(self) -> EvaluationResult:
        targets = self._build_target_results(self._states)

        if self._scenario.condition == "any":
            completed = any(s.matched for s in self._states)
        else:
            completed = all(s.matched for s in self._states)

        total_leaves = self._count_leaves(self._states)
        matched_leaves = self._count_matched_leaves(self._states)
        progress = matched_leaves / total_leaves if total_leaves > 0 else 0.0

        completed_at: datetime | None = None
        if completed:
            times = self._collect_matched_times(self._states)
            if times:
                completed_at = max(times)

        return EvaluationResult(
            scenario_id=self._scenario_id,
            participant_id=self._participant_id,
            env_id=self._env_id,
            condition=self._scenario.condition,
            targets=targets,
            completed=completed,
            completed_at=completed_at,
            progress=progress,
        )

    def _build_target_results(self, states: list[TargetState]) -> list[TargetResult]:
        results = []
        for state in states:
            children = None
            if state.children is not None:
                children = self._build_target_results(state.children)
            results.append(TargetResult(
                target_index=state.index,
                target_type=state.config.type,
                description=state.config.description,
                matched=state.matched,
                matched_at=state.matched_at,
                trigger_event=state.trigger_event,
                children=children,
            ))
        return results

    def _count_leaves(self, states: list[TargetState]) -> int:
        count = 0
        for s in states:
            if s.children is not None:
                count += self._count_leaves(s.children)
            else:
                count += 1
        return count

    def _count_matched_leaves(self, states: list[TargetState]) -> int:
        count = 0
        for s in states:
            if s.children is not None:
                count += self._count_matched_leaves(s.children)
            elif s.matched:
                count += 1
        return count

    def _collect_matched_times(self, states: list[TargetState]) -> list[datetime]:
        times: list[datetime] = []
        for s in states:
            if s.matched_at:
                times.append(s.matched_at)
            if s.children:
                times.extend(self._collect_matched_times(s.children))
        return times

    # ------------------------------------------------------------------
    # Reset
    # ------------------------------------------------------------------

    def _reset_states(self, states: list[TargetState]) -> None:
        for state in states:
            state.matched = False
            state.matched_at = None
            state.trigger_event = None
            if state.children is not None:
                self._reset_states(state.children)
        # Re-inicializar nodos lógicos al estado correcto post-reset
        # (not nodes deben quedar en True nuevamente)
        self._reinit_logical_nodes(states)

    def _reinit_logical_nodes(self, states: list[TargetState]) -> None:
        for state in states:
            if state.children is None:
                continue
            self._reinit_logical_nodes(state.children)
            if state.config.type == "and":
                state.matched = all(c.matched for c in state.children)
            elif state.config.type == "or":
                state.matched = any(c.matched for c in state.children)
            elif state.config.type == "not":
                state.matched = not state.children[0].matched
