# Cómo añadir detección nueva: un Monitor (Capa 2) y su Target (Capa 3)

Guía para contribuidores que quieran extender la capacidad de **detección** de
FlexiPwn: enseñarle a observar un nuevo tipo de actividad en el contenedor
vulnerable y a reconocerla como condición de éxito de un escenario.

Esto implica **siempre dos piezas que trabajan juntas**: un **Monitor** (Capa 2)
que observa el contenedor y produce un evento, y un **Target** (Capa 3) que
consume ese evento y decide si satisface la condición. No tiene sentido una sin
la otra: un Monitor que no alimenta a ningún Target no aporta a la evaluación, y
un Target solo puede evaluar eventos que algún Monitor emita.

> **Requisitos previos:** familiaridad con Python 3, Pydantic v2 y el entorno de
> desarrollo del repo (`uv sync`, `uv run pytest`). Conviene leer antes la
> sección de arquitectura del `README.md` y el `SCHEMA.md`.

---

## 1. Modelo mental: cómo fluye un evento

Las capas 2 y 3 se comunican por un único tipo de dato, el `MonitorEvent`
(`src/flexipwn/layer2/events.py`). Todo gira alrededor de él:

```
Capa 1 (provider)        Capa 2 (monitores)         Capa 3 (motor + targets)
─────────────────        ──────────────────         ────────────────────────
lectura PASIVA    ──▶    Monitor._poll()      ──▶   EvaluationEngine.process_event(event)
(diff, top, /proc,        emite MonitorEvent          │
 logs, captura)           vía on_event(event)         ├─▶ evaluator.matches(event) por cada hoja
                                                       └─▶ propaga nodos and/or/not → EvaluationResult
```

El **Monitor** *produce* `MonitorEvent`s. El **Target** *consume* `MonitorEvent`s
y decide si satisfacen una condición. El `MonitorEvent` es el contrato entre
ambos:

```python
class MonitorEvent(BaseModel):
    timestamp: datetime
    monitor_type: Literal["filesystem", "process", "log", "network"]
    event_type: str          # ej. "file_created", "process_running", "port_listening"
    env_id: str
    participant_id: str
    scenario_id: str
    details: dict[str, Any]  # carga útil específica del tipo de evento
```

**Dónde vive cada pieza.** Los monitores están en `src/flexipwn/layer2/`
(`filesystem.py`, `process.py`, `log.py`, `network.py`). Los targets están en
`src/flexipwn/layer3/` (el schema en `schema.py`, los evaluadores en
`targets/`). El orden natural de trabajo es: primero el Monitor que produce el
evento, luego el Target que lo evalúa.

A lo largo de la guía usamos un mismo caso como hilo conductor: **detectar
cuándo aparece un puerto TCP en escucha nuevo dentro del contenedor** (señal
típica de una *bind shell*). El ejemplo completo, con todo el código, está en la
sección 4.

---

## 2. Parte A — El Target (Capa 3)

La Capa 3 tiene un **patrón de registro limpio**. Un target es una clase que
implementa un único método puro, `matches(event) -> bool`, y se registra en un
diccionario. Toca tres archivos:

- `src/flexipwn/layer3/schema.py` — declara el tipo y sus campos (`TargetConfig`).
- `src/flexipwn/layer3/targets/base.py` — la interfaz `TargetEvaluator` (ABC).
- `src/flexipwn/layer3/targets/registry.py` — el mapa `tipo → clase evaluadora`.

### 2.1. La interfaz `TargetEvaluator`

```python
# src/flexipwn/layer3/targets/base.py
class TargetEvaluator(ABC):
    def __init__(self, config: TargetConfig) -> None:
        self.config = config

    @abstractmethod
    def matches(self, event: MonitorEvent) -> bool:
        """Retorna True si el evento satisface este target.
        Puro — sin side effects, sin I/O."""
        ...
```

> **Regla de oro:** el motor pasa **todos** los eventos (de todos los monitores)
> a **todos** los evaluadores de hoja. Por eso lo primero que hace cada
> `matches()` es filtrar por `event.event_type`. Si no se filtra, el target
> coincide con eventos que no le corresponden.

### 2.2. Pasos

1. **Declarar el tipo en el schema** (`schema.py`): agregarlo al `Literal` de
   `TargetConfig.type`, declarar los campos nuevos que necesite y, si aplica,
   sumar su regla a `validate_fields_for_type`.
2. **Escribir el evaluador**: una subclase de `TargetEvaluator` que implemente
   `matches(self, event) -> bool`. **Debe ser puro**: sin I/O, sin acceso a
   Docker ni al filesystem; solo inspecciona el `event`.
3. **Registrarlo** en `_EVALUATORS` (`registry.py`).
4. **Probar**: un test en `src/flexipwn/tests/` y, opcionalmente, un YAML de
   escenario que lo use.

### 2.3. Notas y trampas comunes

- **El `Literal` del schema no es la fuente de verdad de lo implementado.** Hoy
  incluye `http_response_contains` y `database_query_result`, que **no** están en
  `_EVALUATORS` (se descartaron). `get_evaluator` lanza `NotImplementedError`
  para tipos declarados pero no registrados. La fuente de verdad de lo que
  realmente se evalúa es el diccionario `_EVALUATORS`.
- **No agregar estado.** Las hojas, una vez `matched=True`, no vuelven a `False`
  (lo gestiona el `EvaluationEngine`). El `matches()` debe ser una función pura
  del evento.
- **Targets de red.** Si el tipo nuevo empieza con `network_`, el motor levanta
  automáticamente el `NetworkMonitor` gracias a
  `scenario_requires_network_capture` (que detecta el prefijo recorriendo las
  hojas con `iter_leaf_targets`). Para otros prefijos hay que asegurar que exista
  un monitor que emita el evento (ver Parte B).

---

## 3. Parte B — El Monitor (Capa 2)

> **Estado actual del diseño:** a diferencia de los targets, los monitores **no
> tienen un registro ni una ABC formal**; se cablean **a mano**. Esta sección
> documenta ese cableado tal como está. Es más invasivo que añadir un target:
> toca varios archivos en tres capas.

### 3.1. Interfaz mínima de un monitor

No hay una clase base. El contrato es informal (*duck typing*) y se reduce a:

- Un método **`_poll(self) -> None`**: una iteración de observación. El
  orquestador lo llama periódicamente; el monitor **no** gestiona tiempo ni loop.
- Cuando detecta algo, **emite** llamando a `self._on_event(MonitorEvent(...))`.
- Opcionalmente, un atributo **`_on_stopped(env_id)`** que el monitor invoca si
  detecta que el contenedor desapareció o se detuvo (lo usan hoy
  `FilesystemMonitor` y `ProcessMonitor`; el orquestador los cablea).

La **fuente de datos** varía por monitor y se inyecta por el constructor:
`FilesystemMonitor` y `ProcessMonitor` reciben el `provider` (Capa 1);
`LogMonitor` recibe rutas de log del host; `NetworkMonitor` recibe la ruta del
archivo de captura. Lo único común a todos es `_poll()` + `on_event` + los campos
de identidad (`env_id`, `scenario_id`, `participant_id`).

> **Principio de pasividad (obligatorio):** un monitor **observa desde el host**,
> nunca altera el contenedor. Está prohibido usar `exec_run("ps ...")` o similares
> para observar. Las vías permitidas son `container.diff()`, `container.top()` o
> lectura de `/proc` en el host, lectura de archivos por bind mount, y la captura
> del sidecar tcpdump. Si se necesita un dato nuevo del contenedor, se agrega como
> **lectura pasiva** en el provider (Capa 1).

### 3.2. Puntos que tocar

1. **Clase del monitor** — nuevo archivo `src/flexipwn/layer2/<nombre>.py` con
   `_poll()` que emite `MonitorEvent`(s).
2. **Tipo de monitor** — agregar el valor al `Literal` de
   `MonitorEvent.monitor_type` en `src/flexipwn/layer2/events.py`.
3. **Orquestador** — `src/flexipwn/layer2/orchestrator.py`: aceptar el monitor en
   `__init__` y pollearlo en `_poll_all()`.
4. **Ensamblaje** — `src/flexipwn/layer4/core/daemon_loop.py`, función
   `_build_orchestrator`: instanciar el monitor, pasarlo al orquestador, conectar
   `_on_stopped` si aplica y su *gating* (crearlo solo cuando el escenario lo
   necesite, como hace `NetworkMonitor`).
5. **Provider, si necesita datos nuevos** — `src/flexipwn/layer1/provider.py`:
   agregar un método abstracto de lectura pasiva al ABC `EnvironmentProvider` e
   implementarlo en `DockerRootlessProvider`.

### 3.3. Notas y trampas comunes

- **`_poll()` debe ser rápido y no bloqueante.** Todos los entornos comparten un
  `ThreadPoolExecutor` en el `SuperMonitor`; un `_poll()` lento los degrada a
  todos.
- **Manejar la desaparición del contenedor.** Si la fuente de datos puede fallar
  porque el contenedor se detuvo, hay que capturar la excepción y llamar a
  `self._on_stopped` (ver cómo lo hace `FilesystemMonitor._poll`), en vez de
  propagar el error.
- **No romper la pasividad.** Cualquier observación que requiera tocar el
  contenedor debe entrar por un método nuevo del provider, implementado de forma
  pasiva.
- **El `monitor_type` es un `Literal` cerrado.** Si falta agregar el valor nuevo
  en `events.py`, la construcción del `MonitorEvent` falla la validación de
  Pydantic.

---

## 4. Ejemplo completo end-to-end: detectar puertos en escucha

Recorremos el caso completo: un `PortMonitor` (Capa 2) que detecta puertos TCP en
escucha nuevos, y un target `port_listening` (Capa 3) que lo evalúa. Ningún
monitor observa esto todavía, y además hace falta un dato nuevo del provider, así
que el ejemplo recorre las tres capas.

### 4.1. Capa 1 — dato nuevo en el provider

`src/flexipwn/layer1/provider.py`, agregar al ABC:

```python
@abstractmethod
def get_listening_ports(self, env_id: str) -> list[int]:
    """Retorna los puertos TCP en escucha del contenedor vulnerable.
    DEBE leerse de forma pasiva desde el host (p. ej. /proc/net/tcp del
    network namespace del contenedor). NUNCA usar exec_run('ss'/'netstat')."""
    ...
```

E implementarlo en `DockerRootlessProvider` (esbozo; lo importante es que sea
**pasivo**):

```python
def get_listening_ports(self, env_id: str) -> list[int]:
    # Leer /proc/<pid>/net/tcp del proceso del contenedor desde el host y
    # quedarse con los sockets en estado LISTEN (st == 0x0A). Devolver los
    # puertos (parte alta del campo local_address, en hex).
    ...
```

### 4.2. Capa 2 — el monitor

**Tipo de monitor** (`src/flexipwn/layer2/events.py`):

```python
monitor_type: Literal["filesystem", "process", "log", "network", "port"]  # ← +"port"
```

**Clase del monitor** (`src/flexipwn/layer2/port.py`):

```python
from __future__ import annotations
from collections.abc import Callable
from datetime import UTC, datetime

from flexipwn.layer1.provider import EnvironmentProvider
from flexipwn.layer2.events import MonitorEvent

OnEventCallback = Callable[[MonitorEvent], None]
OnStoppedCallback = Callable[[str], None]


class PortMonitor:
    """Detecta puertos TCP en escucha nuevos respecto al baseline inicial.
    Pasivo: lee vía provider.get_listening_ports(), no ejecuta nada dentro
    del contenedor."""

    def __init__(
        self,
        provider: EnvironmentProvider,
        env_id: str,
        scenario_id: str,
        participant_id: str,
        on_event: OnEventCallback,
        on_stopped: OnStoppedCallback | None = None,
    ) -> None:
        self._provider = provider
        self._env_id = env_id
        self._scenario_id = scenario_id
        self._participant_id = participant_id
        self._on_event = on_event
        self._on_stopped = on_stopped
        # Baseline: puertos que ya escuchaban al inicio → nunca se reportan.
        self._baseline: set[int] = set(provider.get_listening_ports(env_id))
        self._seen: set[int] = set(self._baseline)

    def _poll(self) -> None:
        for port in self._provider.get_listening_ports(self._env_id):
            if port not in self._seen:
                self._seen.add(port)
                self._emit(port)

    def _emit(self, port: int) -> None:
        self._on_event(MonitorEvent(
            timestamp=datetime.now(UTC),
            monitor_type="port",
            event_type="port_listening",
            env_id=self._env_id,
            participant_id=self._participant_id,
            scenario_id=self._scenario_id,
            details={"port": port},
        ))
```

**Orquestador** (`src/flexipwn/layer2/orchestrator.py`):

```python
def __init__(
    self,
    filesystem_monitor: FilesystemMonitor,
    process_monitor: ProcessMonitor,
    log_monitor: LogMonitor | None = None,
    network_monitor: NetworkMonitor | None = None,
    port_monitor: "PortMonitor | None" = None,      # ← NUEVO
    poll_interval: float = 2.0,
    timeout_seconds: int | None = None,
    on_timeout: Callable[[], None] | None = None,
) -> None:
    ...
    self._port = port_monitor                        # ← NUEVO

def _poll_all(self) -> None:
    self._fs._poll()
    self._proc._poll()
    if self._log is not None:
        self._log._poll()
    if self._net is not None:
        self._net._poll()
    if self._port is not None:                       # ← NUEVO
        self._port._poll()
```

**Ensamblaje** (`src/flexipwn/layer4/core/daemon_loop.py`, en
`_build_orchestrator`):

```python
port_monitor = PortMonitor(
    provider=provider,
    env_id=docker_env.env_id,
    scenario_id=docker_env.scenario_id,
    participant_id=docker_env.participant_id,
    on_event=event_sink,
)

orchestrator = MonitorOrchestrator(
    fs_monitor,
    proc_monitor,
    log_monitor=log_monitor,
    network_monitor=network_monitor,
    port_monitor=port_monitor,        # ← NUEVO
    poll_interval=2.0,
)
fs_monitor._on_stopped = on_stopped
proc_monitor._on_stopped = on_stopped
port_monitor._on_stopped = on_stopped  # ← opcional, para que detecte el cierre
```

> **Gating opcional.** Si el monitor es costoso o solo tiene sentido para ciertos
> escenarios, conviene crearlo condicionalmente (como `NetworkMonitor`, que solo
> se levanta si `scenario_requires_network_capture(...)` es verdadero). Para
> `PortMonitor`, que es barato, levantarlo siempre es aceptable.

### 4.3. Capa 3 — el target que lo evalúa

Hasta acá el monitor *registra* la señal, pero ningún escenario puede *exigirla*.
Falta el target que la convierte en condición de éxito, siguiendo la Parte A.

**Schema** (`src/flexipwn/layer3/schema.py`): agregar el tipo y un campo `port`
opcional.

```python
class TargetConfig(BaseModel):
    type: Literal[
        ...
        "network_connection",
        "port_listening",    # ← NUEVO
        ...
    ]
    ...
    port: int | None = None   # ← NUEVO (puerto exacto a exigir; None = cualquiera)
```

**Evaluador** (`src/flexipwn/layer3/targets/port.py`):

```python
from flexipwn.layer2.events import MonitorEvent
from flexipwn.layer3.targets.base import TargetEvaluator


class PortListeningEvaluator(TargetEvaluator):
    """Matchea eventos port_listening. Si config.port está definido, exige ese
    puerto exacto; si es None, cualquier puerto en escucha nuevo cuenta."""

    def matches(self, event: MonitorEvent) -> bool:
        if event.event_type != "port_listening":   # ← filtro obligatorio
            return False
        if self.config.port is None:
            return True
        return event.details.get("port") == self.config.port
```

**Registro** (`src/flexipwn/layer3/targets/registry.py`):

```python
from flexipwn.layer3.targets.port import PortListeningEvaluator   # ← NUEVO

_EVALUATORS: dict[str, type[TargetEvaluator]] = {
    ...
    "network_connection": NetworkConnectionEvaluator,
    "port_listening": PortListeningEvaluator,    # ← NUEVO
}
```

**Uso en un escenario** (YAML):

```yaml
targets:
  - type: port_listening
    port: 4444
    description: "El atacante abrió una bind shell en el puerto 4444"
condition: any
```

---

## 5. Pruebas

- Los tests viven en `src/flexipwn/tests/` y se corren con `uv run pytest`.
- **Target:** es lógica pura → test unitario directo (construir `MonitorEvent` +
  `TargetConfig`, afirmar sobre `matches()`). Ver `test_layer3_engine.py`,
  `test_layer3_log_pattern.py`.
- **Monitor:** se testea con un *provider* o fuente de datos simulada (fake/mock)
  que devuelve datos controlados, verificando los `MonitorEvent` emitidos. Ver
  `test_layer2_filesystem.py`, `test_layer2_process.py`.
- Conviene además un test de integración del flujo evento→evaluación que cubra el
  monitor y su target juntos, siguiendo `test_layer3_engine.py`.
