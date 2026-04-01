# FlexiPwn

Plataforma educativa de ciberseguridad ofensiva que permite crear entornos de práctica aislados para estudiantes. Cada entorno es un par de contenedores (vulnerable + atacante) corriendo en una red interna privada, completamente separados del host y del resto de entornos.

## Arquitectura

FlexiPwn se organiza en 4 capas desacopladas:

```
┌─────────────────────────────────────────────────────────┐
│  Capa 4 — Administración                                │
│  CLI (Typer + Rich) · Persistencia (SQLite / SQLModel)  │
├─────────────────────────────────────────────────────────┤
│  Capa 3 — Motor de evaluación                           │
│  Reglas YAML · Scoring · Feedback al estudiante         │
├─────────────────────────────────────────────────────────┤
│  Capa 2 — Monitoreo pasivo                              │
│  Watchdog · inotify · container.top()                   │
├─────────────────────────────────────────────────────────┤
│  Capa 1 — Entornos virtualizados                        │
│  Docker rootless · Redes internas · Volúmenes aislados  │
└─────────────────────────────────────────────────────────┘
```

**Estado actual:** Capa 1 completamente implementada. Las capas 2–4 están en diseño.

---

## Inicio rápido

Requisitos previos: [Docker rootless](https://docs.docker.com/engine/security/rootless/), Python ≥ 3.12, [uv](https://docs.astral.sh/uv/).

```bash
# 1. Clonar e instalar dependencias
git clone <repo-url> flexipwn && cd flexipwn
uv sync --all-extras

# 2. Verificar que Docker rootless responde
docker info

# 3. Correr el script de prueba manual (necesita la imagen de ejemplo)
docker pull ubuntu:22.04          # imagen liviana para probar
uv run python scripts/manual_test.py

# 4. Correr los tests unitarios (sin Docker)
uv run pytest -m "not integration"

# 5. Correr los tests de integración (requiere Docker rootless activo)
uv run pytest -m integration
```

El script `manual_test.py` crea un entorno completo, ejecuta comandos dentro del contenedor, inspecciona procesos y diferencias de sistema de archivos, prueba el aislamiento de red entre entornos y finalmente destruye todo limpiamente.

---

## Instalación

```bash
uv sync --all-extras
```

Para instalar solo las dependencias de producción (sin herramientas de desarrollo):

```bash
uv sync
```

---

## Capa 1 — Entornos virtualizados

### Diseño

Cada entorno consiste en:

- **Red interna Bridge** (`internal=True`) — sin acceso a internet, sin comunicación entre entornos.
- **Contenedor vulnerable** — la máquina objetivo del ejercicio.
- **Contenedor atacante** *(opcional)* — herramientas de ataque preinstaladas.
- **Directorio de volumen** (`/tmp/flexipwn-volumes/{env_id}/`) — con permisos `0700`, sin bind mounts de directorios del host.

Todos los recursos Docker se etiquetan con `flexipwn.managed=true`, `flexipwn.env_id`, `flexipwn.scenario_id` y `flexipwn.participant_id`, lo que permite limpieza selectiva en caso de fallo.

### Detección de socket Docker

El proveedor busca el socket en este orden:

1. Variable de entorno `DOCKER_HOST`
2. `$XDG_RUNTIME_DIR/docker.sock`
3. `/run/user/{uid}/docker.sock` (ruta por defecto de Docker rootless)

Si no encuentra ninguno, lanza `SocketNotFoundError`.

### Uso básico

```python
from flexipwn.config import FlexiPwnConfig
from flexipwn.layer1 import (
    DockerRootlessProvider,   # importar desde el módulo de implementación
    Environment,
    EnvironmentProvider,
)
from flexipwn.layer1.docker_rootless import DockerRootlessProvider

config = FlexiPwnConfig(volumes_base_path="/tmp/flexipwn-volumes")
provider = DockerRootlessProvider(config)

# Crear entorno (una red + un contenedor vulnerable)
env: Environment = provider.create(
    scenario_id="sudo-vim-privesc",
    participant_id="alice",
    vulnerable_image="flexipwn/vulnerable-sudo:latest",
)
print(env.env_id)        # run-a1b2c3d4
print(env.status)        # running

# Ejecutar un comando dentro del contenedor vulnerable
result = provider.exec_run(env.env_id, "vulnerable", ["whoami"])
print(result.stdout)     # root

# Ver procesos activos (pasivo — usa container.top(), no exec)
processes = provider.get_processes(env.env_id, "vulnerable")
for p in processes:
    print(p.pid, p.cmd)

# Ver cambios en el sistema de archivos vs. imagen base (pasivo — container.diff())
diffs = provider.get_filesystem_diff(env.env_id, "vulnerable")
# kind: 0=modificado, 1=creado, 2=eliminado
for d in diffs:
    print(d["kind"], d["path"])

# Obtener estado del entorno
env = provider.get_status(env.env_id)
print(env.status)        # running / stopped / destroyed

# Recrear contenedores preservando env_id (útil tras un intento fallido)
provider.reset(env.env_id)

# Destruir completamente (contenedores + red + volúmenes)
provider.destroy(env.env_id)

# Limpieza de emergencia — elimina TODOS los recursos FlexiPwn
provider.cleanup_all()
```

### Entorno con contenedor atacante

```python
env = provider.create(
    scenario_id="sudo-vim-privesc",
    participant_id="bob",
    vulnerable_image="flexipwn/vulnerable-sudo:latest",
    attacker_image="flexipwn/kali-light:latest",
)
# Ambos contenedores están en la misma red interna
# y pueden comunicarse entre sí, pero no con el host ni con internet.
```

### Configuración

```python
from flexipwn.config import FlexiPwnConfig

config = FlexiPwnConfig(
    volumes_base_path="/data/flexipwn",  # directorio base de volúmenes
    docker_socket="unix:///run/user/1000/docker.sock",  # None = auto-detect
    container_stop_timeout=10,           # segundos antes de SIGKILL
)
```

### Modelos de datos

| Clase | Descripción | Campos clave |
|---|---|---|
| `Environment` | Estado de un entorno | `env_id`, `scenario_id`, `participant_id`, `status`, `created_at`, `volume_mappings` |
| `ExecResult` | Resultado de un comando | `exit_code`, `stdout`, `stderr` |
| `ProcessInfo` | Proceso dentro del contenedor | `pid`, `ppid`, `euid`, `cmd` |
| `FlexiPwnConfig` | Configuración global | `volumes_base_path`, `docker_socket`, `container_stop_timeout` |

### Excepciones

```
ProviderError                  # base
├── SocketNotFoundError        # socket Docker no encontrado
├── ImageNotFoundError         # imagen no existe localmente
├── ContainerStartError        # el contenedor no arrancó
└── EnvironmentNotFoundError   # env_id no existe
```

---

## Tests

```bash
# Unitarios — no requieren Docker (usan mocks)
uv run pytest -m "not integration"

# Integración — requieren Docker rootless activo
uv run pytest -m integration

# Todo
uv run pytest

# Con cobertura
uv run pytest --cov=flexipwn
```

Los tests de integración usan `ubuntu:22.04` como imagen base. Asegúrate de tener la imagen disponible localmente (`docker pull ubuntu:22.04`).

---

## Principios de seguridad

- **Sin bind mounts del host** — los contenedores no tienen acceso a `/etc`, `/home`, `/root` ni ningún directorio del sistema.
- **Redes internas** — `internal=True` bloquea el tráfico saliente; los contenedores no tienen internet.
- **Aislamiento por entorno** — cada entorno tiene su propia red Bridge; no hay comunicación lateral entre entornos.
- **Monitoreo pasivo** — la observación de procesos y sistema de archivos usa las APIs de Docker (`container.top()`, `container.diff()`) sin ejecutar comandos adicionales dentro del contenedor.
- **Rollback transaccional** — si la creación falla a mitad, los recursos parcialmente creados se limpian automáticamente.
- **Docker rootless** — el daemon corre sin privilegios de root en el host.

---

## Roadmap

| Capa | Descripción | Estado |
|---|---|---|
| 1 | Entornos virtualizados (Docker rootless) | ✅ Implementada |
| 2 | Monitoreo pasivo (watchdog, inotify, container.top) | Diseño |
| 3 | Motor de evaluación de reglas YAML | Diseño |
| 4 | CLI (Typer + Rich) + Persistencia (SQLite / SQLModel) | Diseño |

---

## Licencia

[Apache 2.0](LICENSE)
