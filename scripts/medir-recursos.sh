#!/usr/bin/env bash
#
# medir-recursos-flexipwn.sh
#
# Toma un punto de referencia de la huella de recursos de FlexiPwn para la
# observacion 13 de la comision. Produce una tabla lista para el informe.
#
# REGLAS DE SEGURIDAD DE ESTE SCRIPT
#   - Nunca usa sudo. Si docker necesitara sudo, el script aborta.
#   - Solo usa comandos de docker de lectura: version, info, images, ps, stats.
#   - No borra imagenes, volumenes ni redes. La unica limpieza que hace es
#     `flexipwn run remove --yes` sobre los runs que el propio script creo,
#     que es el camino soportado por la plataforma.
#   - No toca runs ni participantes preexistentes.
#
# USO
#   cd <raiz del repo FlexiPwn>
#   bash medir-recursos-flexipwn.sh            # batch de 10
#   N_BATCH=20 bash medir-recursos-flexipwn.sh # batch de 20
#   SKIP_CLEANUP=1 bash medir-recursos-flexipwn.sh   # deja los runs vivos
#
set -uo pipefail

N_BATCH="${N_BATCH:-10}"
SKIP_CLEANUP="${SKIP_CLEANUP:-0}"
ESCENARIO_YAML="${ESCENARIO_YAML:-scenarios/privesc-demo.yaml}"
ESCENARIO_TITULO="${ESCENARIO_TITULO:-Privilege escalation via sudo vim}"

STAMP="$(date +%Y%m%d-%H%M%S)"
OUTDIR="medicion-recursos-${STAMP}"
mkdir -p "$OUTDIR"
RESUMEN="${OUTDIR}/resumen.md"
FLEXIPWN="uv run flexipwn"

log()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33m[aviso]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 0. Precondiciones
# ---------------------------------------------------------------------------
log "Precondiciones"

command -v docker >/dev/null || die "docker no esta en el PATH."
command -v uv     >/dev/null || die "uv no esta en el PATH."
[ -f pyproject.toml ] || die "Ejecuta el script desde la raiz del repo FlexiPwn."

if ! docker info >/dev/null 2>&1; then
  die "docker info fallo sin sudo. Este script no usa sudo a proposito: revisa que el Docker rootless del usuario este corriendo y que DOCKER_HOST apunte a su socket."
fi

ROOTLESS="no detectado"
if docker info --format '{{range .SecurityOptions}}{{println .}}{{end}}' 2>/dev/null | grep -q rootless; then
  ROOTLESS="si"
else
  warn "docker info no reporta el modo rootless. Anota esto en el informe: los numeros solo son representativos si la instalacion medida es la misma que usa la plataforma."
fi

{
  echo "# Medicion de recursos de FlexiPwn"
  echo
  echo "Fecha: $(date -Is)"
  echo
  echo "## Entorno medido"
  echo
  echo '```'
  echo "host          : $(uname -srm)"
  echo "cpus          : $(nproc) nucleos"
  echo "ram total     : $(awk '/MemTotal/ {printf "%.1f GB", $2/1048576}' /proc/meminfo 2>/dev/null || echo 'n/d')"
  echo "docker        : $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 'n/d')"
  echo "rootless      : ${ROOTLESS}"
  echo "python        : $(python3 --version 2>&1)"
  echo '```'
} > "$RESUMEN"

# ---------------------------------------------------------------------------
# Utilidades de medicion
# ---------------------------------------------------------------------------

# RSS en MiB del arbol de procesos del daemon, leido desde el pid file.
# Se lee /proc/<pid>/status directamente: construir una lista separada por comas
# para `ps -p` fallaba en silencio cuando el daemon no tenia procesos hijos.
daemon_rss_mib() {
  local pidfile="$HOME/.flexipwn/daemon.pid"
  [ -f "$pidfile" ] || { echo "0.0"; return; }
  local pid; pid="$(tr -dc '0-9' < "$pidfile" 2>/dev/null)"
  [ -n "$pid" ] || { echo "0.0"; return; }
  [ -d "/proc/$pid" ] || { echo "0.0"; return; }

  # Arbol de procesos: el daemon y sus descendientes hasta dos niveles.
  local todos="$pid" hijo nieto
  for hijo in $(pgrep -P "$pid" 2>/dev/null); do
    todos="$todos $hijo"
    for nieto in $(pgrep -P "$hijo" 2>/dev/null); do
      todos="$todos $nieto"
    done
  done

  local total=0 rss p
  for p in $todos; do
    rss="$(awk '/^VmRSS:/ {print $2}' "/proc/$p/status" 2>/dev/null)"
    [ -n "$rss" ] && total=$((total + rss))
  done
  awk -v t="$total" 'BEGIN {printf "%.1f", t/1024}'
}

# Contenedores gestionados por FlexiPwn que estan corriendo ahora.
managed_containers() {
  docker ps --filter "label=flexipwn.managed=true" --format '{{.Names}}'
}

# env_id de cada entorno de FlexiPwn presente ahora, sin repetir.
managed_env_ids() {
  docker ps -a --filter "label=flexipwn.managed=true" \
    --format '{{index .Labels "flexipwn.env_id"}}' 2>/dev/null | grep -v '^$' | sort -u
}

# Snapshot de memoria de los contenedores gestionados. Escribe a stdout un CSV.
stats_snapshot() {
  local names; names="$(managed_containers)"
  [ -n "$names" ] || return 0
  # shellcheck disable=SC2086
  docker stats --no-stream --format '{{.Name}},{{.MemUsage}},{{.CPUPerc}}' $names 2>/dev/null
}

# Suma en MiB de la memoria usada por los contenedores gestionados.
managed_mem_mib() {
  stats_snapshot | awk -F',' '
    {
      split($2, a, " / ");
      v = a[1];
      if (v ~ /GiB/) { gsub(/GiB/, "", v); v = v * 1024 }
      else if (v ~ /MiB/) { gsub(/MiB/, "", v) }
      else if (v ~ /KiB/) { gsub(/KiB/, "", v); v = v / 1024 }
      else { gsub(/[A-Za-z]/, "", v) }
      s += v
    }
    END { printf "%.1f", s }'
}

# Muestreador en segundo plano: registra memoria total y RSS del daemon.
SAMPLER_PID=""
start_sampler() {
  local out="$1"
  echo "epoch,contenedores_mib,daemon_rss_mib,n_contenedores" > "$out"
  (
    while true; do
      printf '%s,%s,%s,%s\n' \
        "$(date +%s)" "$(managed_mem_mib)" "$(daemon_rss_mib)" "$(managed_containers | wc -l)" \
        >> "$out"
      sleep 3
    done
  ) &
  SAMPLER_PID=$!
}
stop_sampler() {
  [ -n "$SAMPLER_PID" ] && kill "$SAMPLER_PID" 2>/dev/null
  SAMPLER_PID=""
}
trap 'stop_sampler' EXIT

# ---------------------------------------------------------------------------
# 1. Tamano en disco de las imagenes
# ---------------------------------------------------------------------------
log "Imagenes en disco"

docker images --format '{{.Repository}}:{{.Tag}}\t{{.Size}}' \
  | grep -E 'flexipwn/|netshoot' > "${OUTDIR}/imagenes.txt" || true

{
  echo
  echo "## Imagenes en disco"
  echo
  echo '```'
  cat "${OUTDIR}/imagenes.txt"
  echo '```'
} >> "$RESUMEN"
cat "${OUTDIR}/imagenes.txt"

# ---------------------------------------------------------------------------
# 2. Daemon en reposo
# ---------------------------------------------------------------------------
log "Daemon en reposo"

DAEMON_YA_CORRIA="no"
if $FLEXIPWN daemon status >/dev/null 2>&1; then
  DAEMON_YA_CORRIA="si"
  warn "El daemon ya estaba corriendo. No lo reinicio; la medicion en reposo puede incluir runs previos."
else
  $FLEXIPWN daemon start --detach || die "No se pudo arrancar el daemon."
  sleep 5
fi

RUNS_PREVIOS="$(managed_containers | wc -l)"
managed_env_ids > "${OUTDIR}/env-ids-iniciales.txt"
ENV_IDS_INICIALES="${OUTDIR}/env-ids-iniciales.txt"

if [ "$RUNS_PREVIOS" -gt 0 ]; then
  warn "Hay ${RUNS_PREVIOS} contenedores de FlexiPwn ya corriendo, de $(wc -l < "$ENV_IDS_INICIALES") entornos:"
  sed 's/^/    /' "$ENV_IDS_INICIALES"
  if [ "${FORCE:-0}" != "1" ]; then
    echo
    die "Con entornos preexistentes las cifras por entorno salen mal, porque se calculan restando la base. Limpia primero con 'flexipwn run list' y 'flexipwn run remove <env_id> --yes', o repite con FORCE=1 si solo te interesan los totales."
  fi
  warn "FORCE=1: continuo, pero las cifras POR ENTORNO de esta corrida no son confiables."
fi

RSS_REPOSO="$(daemon_rss_mib)"
MEM_BASE="$(managed_mem_mib)"
echo "daemon en reposo: ${RSS_REPOSO} MiB de RSS"

# ---------------------------------------------------------------------------
# 3. Un entorno: tiempo de arranque y huella
# ---------------------------------------------------------------------------
log "Un entorno"

$FLEXIPWN scenario load "$ESCENARIO_YAML" >/dev/null 2>&1 || \
  warn "scenario load fallo o el escenario ya estaba cargado. Continuo."

cat > "${OUTDIR}/batch-1.yaml" <<EOF
assignments:
  - scenario: "${ESCENARIO_TITULO}"
    count: 1
EOF

T0=$(date +%s.%N)
$FLEXIPWN run batch-start "${OUTDIR}/batch-1.yaml" --output "${OUTDIR}/runs-1.csv" \
  > "${OUTDIR}/batch-1.log" 2>&1
T1=$(date +%s.%N)
TIEMPO_1=$(awk -v a="$T0" -v b="$T1" 'BEGIN {printf "%.1f", b-a}')

sleep 8   # deja que el escenario termine de inicializar antes de medir
stats_snapshot > "${OUTDIR}/stats-1.csv"
MEM_1="$(managed_mem_mib)"
RSS_1="$(daemon_rss_mib)"
N_CONT_1="$(managed_containers | wc -l)"
MEM_ENTORNO=$(awk -v t="$MEM_1" -v b="$MEM_BASE" 'BEGIN {printf "%.1f", t-b}')

echo "tiempo de arranque : ${TIEMPO_1} s"
echo "contenedores       : ${N_CONT_1} (base ${RUNS_PREVIOS})"
echo "memoria del entorno: ${MEM_ENTORNO} MiB"

# ---------------------------------------------------------------------------
# 4. Batch de N entornos
# ---------------------------------------------------------------------------
log "Batch de ${N_BATCH} entornos"

cat > "${OUTDIR}/batch-n.yaml" <<EOF
assignments:
  - scenario: "${ESCENARIO_TITULO}"
    count: ${N_BATCH}
EOF

start_sampler "${OUTDIR}/muestreo.csv"
T0=$(date +%s.%N)
$FLEXIPWN run batch-start "${OUTDIR}/batch-n.yaml" --output "${OUTDIR}/runs-n.csv" \
  > "${OUTDIR}/batch-n.log" 2>&1
T1=$(date +%s.%N)
TIEMPO_N=$(awk -v a="$T0" -v b="$T1" 'BEGIN {printf "%.1f", b-a}')
sleep 15   # deja que todos los entornos terminen de inicializar
stats_snapshot > "${OUTDIR}/stats-n.csv"
sleep 5    # una muestra mas ya en regimen, para que el pico no quede corto
stop_sampler

MEM_N="$(managed_mem_mib)"
RSS_N="$(daemon_rss_mib)"
N_CONT_N="$(managed_containers | wc -l)"

# ¿Se crearon todos los entornos que pedimos? batch-start es tolerante a fallos:
# si un entorno no se puede crear, lo registra y sigue con el siguiente, de modo
# que el CSV solo trae los que si se crearon.
CREADOS_N=0
[ -f "${OUTDIR}/runs-n.csv" ] && CREADOS_N=$(($(wc -l < "${OUTDIR}/runs-n.csv") - 1))
if [ "$CREADOS_N" -lt "$N_BATCH" ]; then
  warn "El lote pidio ${N_BATCH} entornos y solo se crearon ${CREADOS_N}. Revisa ${OUTDIR}/batch-n.log: probablemente se alcanzo un limite del servidor (memoria, puertos o descriptores). Las cifras de este lote describen ${CREADOS_N} entornos, no ${N_BATCH}."
fi
PICO=$(awk -F',' 'NR>1 && $2>m {m=$2} END {printf "%.1f", m}' "${OUTDIR}/muestreo.csv")
TIEMPO_POR_ENTORNO=$(awk -v t="$TIEMPO_N" -v n="$N_BATCH" 'BEGIN {printf "%.1f", t/n}')

echo "tiempo total       : ${TIEMPO_N} s (${TIEMPO_POR_ENTORNO} s por entorno)"
echo "contenedores       : ${N_CONT_N}"
echo "memoria total      : ${MEM_N} MiB (pico observado ${PICO} MiB)"
echo "daemon bajo carga  : ${RSS_N} MiB de RSS"

# ---------------------------------------------------------------------------
# 5. Resumen
# ---------------------------------------------------------------------------
TOTAL_ENTORNOS=$((N_BATCH + 1))
MEM_POR_ENTORNO=$(awk -v t="$MEM_N" -v b="$MEM_BASE" -v n="$TOTAL_ENTORNOS" \
  'BEGIN {printf "%.1f", (t-b)/n}')

{
  echo
  echo "## Resultados"
  echo
  echo "| Magnitud | Valor |"
  echo "|---|---|"
  echo "| Daemon en reposo | ${RSS_REPOSO} MiB de RSS |"
  echo "| Daemon con ${TOTAL_ENTORNOS} entornos activos | ${RSS_N} MiB de RSS |"
  echo "| Contenedores por entorno | $(( (N_CONT_1 - RUNS_PREVIOS) )) |"
  echo "| Memoria de un entorno aislado | ${MEM_ENTORNO} MiB |"
  echo "| Memoria promedio por entorno con ${TOTAL_ENTORNOS} activos | ${MEM_POR_ENTORNO} MiB |"
  echo "| Memoria total de ${TOTAL_ENTORNOS} entornos | ${MEM_N} MiB (pico ${PICO} MiB) |"
  echo "| Arranque de un entorno en frio | ${TIEMPO_1} s |"
  echo "| Arranque de ${N_BATCH} entornos por lotes | ${TIEMPO_N} s (${TIEMPO_POR_ENTORNO} s por entorno) |"
  echo
  echo "Escenario medido: ${ESCENARIO_TITULO}"
  echo
  echo "Notas: el arranque por lotes es secuencial. Compara el costo por entorno"
  echo "del batch (${TIEMPO_POR_ENTORNO} s) contra el arranque en frio de uno solo"
  echo "(${TIEMPO_1} s) para ver si el costo por entorno crece con la cantidad de"
  echo "entornos activos. Cada entorno se compone del contenedor vulnerable, el"
  echo "contenedor atacante y, cuando el escenario declara objetivos de red, el"
  echo "sidecar de captura, de ahi que el conteo por entorno sea 2 o 3."
  echo
  echo "## Archivos crudos"
  echo
  echo "- \`muestreo.csv\`: serie de tiempo del batch (memoria y RSS cada 3 s)"
  echo "- \`stats-1.csv\`, \`stats-n.csv\`: docker stats por contenedor"
  echo "- \`runs-1.csv\`, \`runs-n.csv\`: runs creados"
  echo "- \`batch-1.log\`, \`batch-n.log\`: salida de batch-start"
} >> "$RESUMEN"

# ---------------------------------------------------------------------------
# 6. Limpieza de lo que creo este script
# ---------------------------------------------------------------------------
if [ "$SKIP_CLEANUP" = "1" ]; then
  log "Limpieza omitida (SKIP_CLEANUP=1). Los runs quedan vivos."
else
  log "Limpieza de los runs creados por este script"

  # La lista a borrar son los env_id de los CSV mas cualquier entorno que exista
  # ahora y no existiera al empezar. Lo segundo cubre los entornos que el lote
  # alcanzo a crear parcialmente y que por eso nunca llegaron al CSV. Los
  # entornos que ya estaban antes de arrancar no se tocan nunca.
  {
    for csv in "${OUTDIR}/runs-1.csv" "${OUTDIR}/runs-n.csv"; do
      [ -f "$csv" ] && tail -n +2 "$csv" | awk -F',' '{print $3}'
    done
    comm -13 "$ENV_IDS_INICIALES" <(managed_env_ids)
  } | grep -v '^$' | sort -u > "${OUTDIR}/a-borrar.txt"

  while read -r env_id; do
    [ -n "$env_id" ] || continue
    $FLEXIPWN run stop "$env_id"          >/dev/null 2>&1
    $FLEXIPWN run remove "$env_id" --yes  >/dev/null 2>&1 \
      && echo "  eliminado ${env_id}" \
      || warn "  no se pudo eliminar ${env_id}, revisalo a mano"
  done < "${OUTDIR}/a-borrar.txt"

  # Verificacion: ¿quedo algo vivo que no estuviera antes?
  RESTOS="$(comm -13 "$ENV_IDS_INICIALES" <(managed_env_ids))"
  if [ -n "$RESTOS" ]; then
    warn "Quedaron entornos sin eliminar. Bajalos con 'flexipwn run remove <env_id> --yes':"
    echo "$RESTOS" | sed 's/^/    /'
  else
    echo "  verificado: no quedaron entornos de esta corrida"
  fi
fi

if [ "$DAEMON_YA_CORRIA" = "no" ]; then
  log "Deteniendo el daemon (lo habia arrancado este script)"
  $FLEXIPWN daemon stop >/dev/null 2>&1
fi

log "Listo. Resumen en ${RESUMEN}"
echo
cat "$RESUMEN"
