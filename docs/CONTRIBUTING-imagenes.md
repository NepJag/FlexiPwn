# Cómo construir una imagen compatible con FlexiPwn

Guía para educadores que quieran montar un escenario sobre su **propia imagen
vulnerable**, en lugar de usar las que vienen en `docker/`.

FlexiPwn observa el sistema vulnerable **desde fuera**: no instala agentes, no
ejecuta nada dentro del contenedor y no modifica su estado. Esa pasividad es la
que impone los requisitos de esta guía. Una imagen que no los cumple igual
arranca, pero sus objetivos pueden no dispararse nunca o dispararse solos.

> **Requisitos previos:** saber escribir un `Dockerfile` y haber leído la
> sección `environment` de [`SCHEMA.md`](../SCHEMA.md).

---

## Resumen

| Requisito | Qué pasa si no se cumple |
|---|---|
| 1. Punto de entrada alcanzable | El estudiante no puede llegar al objetivo |
| 2. Arranque observable | La línea base queda sucia y aparecen falsos positivos |
| 3. Estado inicial estable | Objetivos que se disparan solos |
| 4. Registros en rutas declaradas | Los targets `log_pattern` nunca se disparan |
| 5. Tráfico en claro | Los targets de red nunca coinciden |
| 6. Sin privilegios especiales | El contenedor no arranca bajo Docker rootless |

---

## 1. Punto de entrada alcanzable

El estudiante trabaja desde el **contenedor atacante** y necesita llegar al
vulnerable por la red del escenario. La imagen debe exponer al menos un
servicio:

- **SSH**, si quieres que el estudiante entre a una shell del objetivo. Es lo
  que hace `docker/privesc/`: instala `openssh-server`, crea un usuario con
  clave conocida y arranca `sshd -D`.
- **HTTP u otro servicio de red**, si el ataque es remoto. Es lo que hacen
  `docker/sqli-mysql/` y `docker/vuln-command-injection/`.

El vulnerable es alcanzable desde el atacante por el nombre
`flexipwn-<env_id>-vulnerable`. **No fijes IPs ni hostnames en la imagen**: la
plataforma crea una red por entorno y asigna direcciones dinámicamente.

Declara los puertos que quieras publicar hacia el anfitrión en el campo `ports`
del escenario, no en el `Dockerfile`. `EXPOSE` es documentación y no basta.

## 2. Arranque observable

Al crear el entorno, la Capa 2 toma una **línea base** del sistema de archivos y
de los procesos. Todo lo que exista en ese momento se marca como preexistente y
no genera eventos. Si la línea base se toma mientras el servicio todavía se está
inicializando, los archivos y procesos que aparezcan después se reportarán como
si los hubiera creado el estudiante.

Dos formas de evitarlo, en orden de preferencia:

```dockerfile
# Preferida: HEALTHCHECK. La plataforma espera a que el contenedor esté healthy.
HEALTHCHECK --interval=2s --timeout=2s --start-period=5s --retries=5 \
    CMD pgrep sshd || exit 1
```

```yaml
# Alternativa: espera fija en el escenario, si la imagen no puede declarar
# un HEALTHCHECK confiable.
environment:
  startup_delay_seconds: 20
```

Si el servicio es lento en arrancar (MySQL, por ejemplo), usa **ambos**: un
`HEALTHCHECK` con `--start-period` generoso y un `startup_delay_seconds` acorde.

## 3. Estado inicial estable

Cualquier cosa que cambie sola después de la línea base se ve igual que un
avance del estudiante. Evita en la imagen:

- `cron`, `logrotate`, `systemd` timers o cualquier tarea periódica.
- Servicios que reescriban archivos bajo rutas vigiladas por targets.
- Procesos que se reinicien solos y vuelvan a aparecer con otro PID.
- Actualizaciones automáticas de paquetes.

Regla práctica: deja el contenedor corriendo un par de minutos sin tocarlo y
comprueba que `docker diff` no siga creciendo.

## 4. Registros en rutas declaradas

Si el escenario usa targets `log_pattern`, hay que entender **cómo** FlexiPwn
lee esos registros, porque tiene dos consecuencias que sorprenden.

Cada ruta de `environment.log_paths` se resuelve a su **directorio padre**, y
ese directorio se monta desde el anfitrión con permiso de escritura
(`src/flexipwn/layer1/docker_rootless.py`). O sea:

```yaml
environment:
  log_paths:
    - "/var/log/mysql/general.log"   # se monta todo /var/log/mysql
```

**Consecuencia 1: el directorio queda vacío al arrancar.** El montaje tapa lo
que la imagen tuviera dentro. El directorio debe existir en la imagen y ser
escribible por el usuario que corre el servicio, o este fallará al abrir su
archivo de log:

```dockerfile
RUN mkdir -p /var/log/mysql && chown mysql:adm /var/log/mysql && chmod 775 /var/log/mysql
```

**Consecuencia 2: esos archivos no existen para los targets de filesystem.** El
monitor de sistema de archivos usa `container.diff()`, que solo ve la capa de
escritura del contenedor y no los montajes. Un archivo bajo un directorio de
`log_paths` **nunca** disparará un `file_created` ni un `file_modified`. Si
necesitas ambas cosas, usa rutas distintas.

Además, el servicio debe escribir a un **archivo**, no solo a `stdout`. Si tu
aplicación registra a la salida estándar, redirígela dentro de la imagen:

```dockerfile
CMD ["sh", "-c", "mi-servicio >> /var/log/app/servicio.log 2>&1"]
```

## 5. Tráfico en claro

El monitor de red es un contenedor `sidecar` que comparte el espacio de red del
vulnerable y corre `tcpdump`. Lee bytes del cable: **no descifra TLS**.

- El tráfico que deba disparar targets `network_payload` tiene que viajar sin
  cifrar. En el escenario de MySQL esto se logra con `tls_version=` vacío en la
  configuración del servidor.
- Los targets `network_connection` sí funcionan con tráfico cifrado, porque
  solo miran el establecimiento de la conexión y no su contenido.
- Ajusta `environment.capture_filter` al puerto real del servicio
  (`"port 3306"`, `"port 4444"`). Un filtro que no coincide con el tráfico
  produce una captura vacía. Dejarlo en blanco captura todo, a costa de más
  ruido.

## 6. Sin privilegios especiales

La plataforma corre sobre **Docker rootless**. La imagen no puede depender de:

- `--privileged` ni capacidades adicionales (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`).
- Montar el socket del daemon de contenedores.
- Escribir en `/sys` o `/proc` del anfitrión.
- Puertos privilegiados en el anfitrión (por debajo de 1024).

Un escenario que necesite alguna de estas cosas no es apto para FlexiPwn en su
forma actual.

---

## Lista de verificación antes de cargar el escenario

```bash
# 1. La imagen construye
docker build -t mi/vulnerable docker/mi-vulnerable/

# 2. Arranca sola y queda healthy
docker run -d --name prueba mi/vulnerable
docker inspect --format '{{.State.Health.Status}}' prueba

# 3. El estado no cambia solo: espera y comprueba que el diff no crezca
docker diff prueba | wc -l && sleep 120 && docker diff prueba | wc -l

# 4. El servicio responde
docker exec prueba pgrep sshd        # o el chequeo que corresponda

# 5. El escenario es válido
uv run flexipwn scenario validate scenarios/mi-escenario.yaml
```

Después de cargarlo, arranca un run y usa el modo verboso para ver la cadena
completa de evento a objetivo:

```bash
uv run flexipwn --verbose run start
```

---

## Imágenes de referencia

Las tres imágenes de `docker/` sirven como plantilla:

- `docker/privesc/` es la más simple: SSH, un usuario, una configuración de
  `sudo` mal puesta, sin red ni registros.
- `docker/sqli-mysql/` es la más completa: HTTP, base de datos, registros en un
  directorio montado y tráfico en claro.
- `docker/vuln-command-injection/` es el caso de red: HTTP y una conexión
  saliente que dispara un `network_connection`.

Para extender la **detección** en lugar de la imagen, es decir, para añadir un
monitor o un tipo de target nuevo, la guía es
[`CONTRIBUTING-monitores-targets.md`](./CONTRIBUTING-monitores-targets.md).
