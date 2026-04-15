# Guía de escenarios FlexiPwn

## Introducción

Cada escenario de FlexiPwn se define en un archivo YAML que describe el entorno Docker, las condiciones de victoria y las pistas para el estudiante. La plataforma lee este archivo al crear un "run" y lo usa para evaluar automáticamente si el participante ha completado los objetivos — sin intervención del instructor.

El motor de evaluación es completamente pasivo: nunca ejecuta comandos en el contenedor ni modifica el entorno. Solo observa eventos (archivos creados, procesos activos, respuestas HTTP) y los compara contra los targets que defines aquí. Cuando se cumplen las condiciones, el run se marca como completado y la plataforma registra la hora y el progreso.

---

## Estructura completa anotada

```yaml
# Metadatos del escenario
title: "Privesc via sudo vim"           # Nombre corto (aparece en la UI)
description: >                          # Descripción larga para el estudiante
  Consigue acceso root explotando una
  configuración insegura de sudo.
author: "instructor@universidad.edu"    # Autor — solo informativo
level: beginner                         # beginner | intermediate | advanced
category: pwning                        # pwning | web | database | forensics | reversing

# Entorno Docker
environment:
  image: "flexipwn/debian-sudovim:1.0"  # Imagen del contenedor vulnerable (obligatorio)
  attacker_image: null                  # Imagen del atacante — null si no se necesita
  log_paths:                            # Rutas de logs a monitorear (Capa 2)
    - /var/log/auth.log
  volumes: {}                           # Volúmenes extra: {host_path: container_path}
  network: null                         # Red Docker custom — null para red por defecto
  ports: []                             # Puertos a exponer: ["8080:80", "3306:3306"]

# Pistas mostradas al estudiante en orden (opcional)
hints:
  - "Revisa qué comandos puedes ejecutar como root con sudo -l"
  - "vim tiene modo shell. Busca cómo escapar al sistema operativo desde dentro."
  - "Una vez dentro de vim como root, prueba :!/bin/bash"

# Condición de victoria: "any" (basta con uno) | "all" (todos requeridos)
condition: all

# Tiempo máximo del run en segundos (default: 1800 = 30 min)
timeout_seconds: 1800

# Lista de objetivos a evaluar
targets:
  - type: file_created
    description: "El estudiante creó el archivo /root/pwned.txt"
    path: /root/pwned.txt
```

---

## Tipos de target disponibles

### `file_created`

Detecta cuando un archivo nuevo aparece en el filesystem del contenedor.

| Campo | Obligatorio | Descripción |
|-------|-------------|-------------|
| `path` | Sí | Path exacto del archivo, o directorio terminado en `/` |
| `pattern` | No | Glob para filtrar por nombre (solo si `path` termina en `/`) |

**Ejemplo — archivo exacto:**
```yaml
- type: file_created
  description: "Archivo de bandera creado por el estudiante"
  path: /root/pwned.txt
```

**Ejemplo — cualquier `.txt` en un directorio:**
```yaml
- type: file_created
  description: "Cualquier archivo .txt creado en /tmp/"
  path: /tmp/
  pattern: "*.txt"
```

---

### `file_modified`

Detecta cuando un archivo preexistente es modificado.

| Campo | Obligatorio | Descripción |
|-------|-------------|-------------|
| `path` | Sí | Path exacto del archivo a vigilar |

**Ejemplo:**
```yaml
- type: file_modified
  description: "El archivo /etc/passwd fue modificado"
  path: /etc/passwd
```

---

### `file_exists`

Verifica periódicamente (polling) que un archivo exista y opcionalmente contenga un texto específico.

| Campo | Obligatorio | Descripción |
|-------|-------------|-------------|
| `path` | Sí | Path exacto del archivo |
| `contains` | No | Substring que debe aparecer en el contenido del archivo |

**Ejemplo — solo existencia:**
```yaml
- type: file_exists
  description: "El archivo de bandera existe"
  path: /root/flag.txt
```

**Ejemplo — con contenido esperado:**
```yaml
- type: file_exists
  description: "La bandera contiene el texto correcto"
  path: /root/flag.txt
  contains: "FLAG{privesc_ok}"
```

---

### `process_running` _(disponible en versión futura)_

Detecta cuando un proceso específico está corriendo con un usuario (euid) determinado.

| Campo | Obligatorio | Descripción |
|-------|-------------|-------------|
| `euid` | Sí | UID efectivo del proceso (0 = root) |
| `cmd_contains` | Sí | Substring que debe aparecer en la línea de comando |

```yaml
# Ejemplo (versión futura)
- type: process_running
  description: "Shell corriendo como root"
  euid: 0
  cmd_contains: "/bin/bash"
```

---

### `log_pattern` _(disponible en versión futura)_

Detecta cuando una línea de log estructurado coincide con un conjunto de campos.

| Campo | Obligatorio | Descripción |
|-------|-------------|-------------|
| `field_matches` | Sí | Dict de campo → valor esperado |

```yaml
# Ejemplo (versión futura)
- type: log_pattern
  description: "Login exitoso como root en auth.log"
  field_matches:
    user: root
    action: session_opened
```

---

### `http_response_contains` _(disponible en versión futura)_

Verifica que una respuesta HTTP del contenedor tenga cierto contenido.

| Campo | Obligatorio | Descripción |
|-------|-------------|-------------|
| `url_path` | Sí | Ruta de la petición (e.g. `/admin`) |
| `body_contains` | No | Substring esperado en el cuerpo |
| `status_code` | No | Código HTTP esperado (e.g. `200`) |

```yaml
# Ejemplo (versión futura)
- type: http_response_contains
  description: "Login bypass exitoso"
  url_path: /admin
  status_code: 200
  body_contains: "Bienvenido, admin"
```

---

### `database_query_result` _(disponible en versión futura)_

Verifica el resultado de una consulta SQL en la base de datos del contenedor.

| Campo | Obligatorio | Descripción |
|-------|-------------|-------------|
| `table` | Sí | Tabla sobre la que se consulta |
| `result_contains` | Sí | Valor esperado en el resultado |

```yaml
# Ejemplo (versión futura)
- type: database_query_result
  description: "Dato exfiltrado de la tabla users"
  table: users
  result_contains: "admin@corp.com"
```

---

## Ejemplos completos

### Escenario de pwning — Privesc via sudo vim

```yaml
title: "Privesc via sudo vim"
description: >
  El usuario `student` puede ejecutar vim como root usando sudo.
  Escapa al shell de root y deja evidencia de tu acceso.
author: "instructor@universidad.edu"
level: beginner
category: pwning

environment:
  image: "flexipwn/debian-sudovim:1.0"
  log_paths:
    - /var/log/auth.log

hints:
  - "¿Qué comandos puedes ejecutar como root? Prueba: sudo -l"
  - "vim tiene un modo de comandos de shell. ¿Cómo se activa?"
  - "Desde dentro de vim (como root): :!/bin/bash"

condition: all
timeout_seconds: 1800

targets:
  - type: file_created
    description: "Archivo /root/pwned.txt creado (evidencia de root)"
    path: /root/pwned.txt

  - type: file_modified
    description: "/etc/passwd fue modificado (añadiste un usuario root)"
    path: /etc/passwd
```

---

### Escenario de web — SQLi login bypass

```yaml
title: "SQL Injection — Login bypass"
description: >
  La aplicación web tiene un login vulnerable a SQL injection clásica.
  Entra como administrador sin conocer la contraseña.
author: "instructor@universidad.edu"
level: intermediate
category: web

environment:
  image: "flexipwn/php-sqli-lab:1.0"
  ports:
    - "8080:80"
  log_paths:
    - /var/log/apache2/access.log

hints:
  - "Observa cómo la aplicación construye la query SQL con tu input."
  - "¿Qué pasa si escribes una comilla simple en el campo usuario?"
  - "Intenta: ' OR '1'='1 como usuario (y cualquier contraseña)."

condition: any
timeout_seconds: 3600

targets:
  - type: file_created
    description: "Archivo de sesión admin creado tras login exitoso"
    path: /var/www/html/sessions/
    pattern: "admin_*.sess"

  - type: file_exists
    description: "El archivo de bandera fue leído (solo accesible como admin)"
    path: /var/www/html/admin/flag.txt
    contains: "FLAG{sqli_bypass}"
```

---

## Condiciones de victoria

La clave `condition` determina cuántos targets deben cumplirse para considerar el escenario completado.

### `condition: all`

**Todos** los targets deben matchear. Úsalo cuando quieras que el estudiante demuestre varios pasos del ataque.

```
Objetivo 1: modificar /etc/passwd   ✓
Objetivo 2: crear /root/pwned.txt   ✓
→ Completado
```

Ideal para: ejercicios de privesc con múltiples etapas, cadenas de explotación.

### `condition: any`

**Basta con que uno** de los targets matchee. Úsalo cuando hay múltiples caminos válidos al mismo objetivo.

```
Objetivo 1: bypass via SQLi     ✓   ← matcheó primero
Objetivo 2: bypass via NoSQLi   ✗
→ Completado
```

Ideal para: escenarios con varias técnicas válidas, CTFs donde el path importa menos que llegar al flag.

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
  path: /root/pwned.txt
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
  path: /root/pwned.txt
  pattern: "*.txt"

# Correcto — vigilar cualquier .txt en el directorio
- type: file_created
  path: /root/
  pattern: "*.txt"
```

---

### 5. `contains` con `file_created` en vez de `file_exists`

**Problema:** El campo `contains` (verificar contenido) solo funciona con `file_exists`. En `file_created` no tiene efecto — ese tipo solo detecta la creación, no lee el contenido.

```yaml
# Incorrecto — contains se ignora en file_created
- type: file_created
  path: /root/flag.txt
  contains: "FLAG{ok}"

# Correcto — usar file_exists para verificar contenido
- type: file_exists
  path: /root/flag.txt
  contains: "FLAG{ok}"
```

---

### 6. Imagen Docker no disponible localmente

**Error en tiempo de ejecución:**
```
ImageNotFoundError: La imagen 'flexipwn/mi-lab:1.0' no existe localmente ni en el registro.
```

**Causa:** La imagen especificada en `environment.image` no está disponible. La plataforma no construye imágenes automáticamente.

**Corrección:** Asegúrate de que la imagen esté publicada en un registro accesible o disponible localmente con `docker pull`.
