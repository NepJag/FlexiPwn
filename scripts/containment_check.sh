#!/usr/bin/env bash
#
# containment_check.sh — Chequeo read-only de la resistencia de FlexiPwn frente a
# los runc escapes (CVE-2025-31133/52565/52881) y Copy Fail (CVE-2026-31431).
#
# Auto-detecta dónde corre y hace solo los chequeos que tienen sentido ahí:
#   - En el HOST      : ¿Docker rootless? ¿runc parcheado? (fixes 1.2.8/1.3.3/1.4.0-rc.3)
#   - En el CONTENEDOR: ¿root-en-contenedor queda contenido? (uid_map/rootless, caps,
#                       AF_ALG, core_pattern, sysrq)
# Forzar el modo con: FLEXIPWN_MODE=host|container
#
# Cada chequeo reporta:
#   [CONTENIDO]  el vector está cerrado (bueno para FlexiPwn)
#   [  FUGA   ]  el vector permitiría tocar el host (malo)
# y va precedido de una nota (atenuada) que explica qué revisa y su rol en el CVE.
#
# NO ejecuta exploits. NO escribe en /proc/sysrq-trigger (solo consulta el bit de
# escritura). En core_pattern reescribe el MISMO valor (inocuo) para detectar si
# es escribible.
#
# Uso:
#   Host:        bash scripts/containment_check.sh
#   Contenedor:  docker exec -i flexipwn-<env_id>-attacker bash -s < scripts/containment_check.sh
#                docker run --rm -i flexipwn/attacker bash -s < scripts/containment_check.sh
#   (imagen con bash + python3 o perl; ubuntu:22.04 trae perl-base.)
#
set -u

if [ -t 1 ]; then
  G=$'\033[32m'; R=$'\033[31m'; B=$'\033[34m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; N=$'\033[0m'
else
  G=""; R=""; B=""; DIM=""; BOLD=""; N=""
fi

PASS=0; FAIL=0
contained() { printf '  %s[CONTENIDO]%s %s\n' "$G" "$N" "$*"; PASS=$((PASS+1)); }
leak()      { printf '  %s[  FUGA   ]%s %s\n' "$R" "$N" "$*"; FAIL=$((FAIL+1)); }
info()      { printf '  %s[  info   ]%s %s\n' "$B" "$N" "$*"; }
sec()       { printf '\n%s== %s ==%s\n' "$BOLD" "$*" "$N"; }
why()       { printf '  %s%s%s\n' "$DIM" "$*" "$N"; }   # nota explicativa (atenuada)

# ge A B -> 0 (true) si A >= B en orden de versión (usa sort -V).
ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]; }

# -----------------------------------------------------------------------------
# Detección de contexto: ¿corro en el host o dentro de un contenedor?
# -----------------------------------------------------------------------------
detect_mode() {
  if [ -e /.dockerenv ] || grep -qaE 'docker|containerd|kubepods' /proc/1/cgroup 2>/dev/null; then
    echo container
  elif command -v docker >/dev/null 2>&1 || command -v runc >/dev/null 2>&1; then
    echo host
  else
    echo container   # sin pistas de host: asumir contenedor
  fi
}
MODE="${FLEXIPWN_MODE:-$(detect_mode)}"

printf '%s' "$BOLD"
echo "============================================================"
echo " FlexiPwn — Resistencia (runc escapes + Copy Fail)"
echo "============================================================"
printf '%s' "$N"
info "Modo: ${MODE}  (forzar con FLEXIPWN_MODE=host|container)"

# =============================================================================
if [ "$MODE" = "host" ]; then
# =============================================================================
# Chequeos de HOST: postura del runtime (runc no es visible desde el contenedor).

  sec "Modo rootless de Docker (runc escapes CVE-2025-31133/52565/52881)"
  why "Revisa si el daemon Docker corre sin privilegios de root en el host."
  why "En rootless, un escape de runc aterriza como usuario sin privilegios del host (no root), quitándole casi todo el impacto a CVE-2025-31133/52565/52881."
  if command -v docker >/dev/null 2>&1; then
    if docker info 2>/dev/null | grep -qi 'rootless'; then
      contained "Docker rootless: un escape aterriza como usuario sin privilegios del host"
    else
      leak "Docker NO rootless (rootful): un escape sería root del host"
    fi
  else
    info "docker no está en PATH: no se pudo determinar rootless"
  fi

  sec "Versión de runc — CVE-2025-31133/52565/52881 (fixes: 1.2.8/1.3.3/1.4.0-rc.3)"
  why "Compara la versión de runc instalada contra la primera versión parcheada de cada serie."
  why "Los tres runc escapes abusan de symlinks/procfs durante la creación o el exec del contenedor para escribir en el host; esas versiones cierran el agujero (CVE-2025-31133/52565/52881)."
  RUNC_VER=""
  if command -v runc >/dev/null 2>&1; then
    RUNC_VER="$(runc --version 2>/dev/null | awk '/runc version/{print $3; exit}')"
  fi
  if [ -z "$RUNC_VER" ] && command -v docker >/dev/null 2>&1; then
    RUNC_VER="$(docker info 2>/dev/null | awk -F': ' '/[Rr]unc [Vv]ersion/{print $2; exit}')"
  fi
  if [ -z "$RUNC_VER" ]; then
    info "no se pudo determinar la versión de runc (revisar 'runc --version' o 'docker info')"
  else
    info "runc version: $RUNC_VER"
    V="${RUNC_VER%%+*}"                       # 1.3.5+commit  ->  1.3.5
    MAJMIN="$(printf '%s' "$V" | cut -d. -f1-2)"
    case "$MAJMIN" in
      1.2) ge "$V" 1.2.8 && OK=1 || OK=0 ;;
      1.3) ge "$V" 1.3.3 && OK=1 || OK=0 ;;
      1.4)
        case "$V" in
          *-rc.*) RC="$(printf '%s' "$V" | sed -n 's/.*-rc\.\([0-9]*\).*/\1/p')"
                  [ "${RC:-0}" -ge 3 ] && OK=1 || OK=0 ;;
          *)      OK=1 ;;                      # 1.4.0 estable o superior
        esac ;;
      *) if ge "$V" 1.5; then OK=1; else OK=-1; fi ;;   # >=1.5 parcheado; <1.2 desconocido
    esac
    case "$OK" in
      1) contained "runc $V parcheado contra los runc escapes" ;;
      0) leak "runc $V VULNERABLE: actualizar a >= 1.2.8 / 1.3.3 / 1.4.0-rc.3" ;;
      *) info "serie $MAJMIN fuera de la tabla de fixes; verificar manualmente" ;;
    esac
  fi

  info "Para la contención dentro del entorno, corre este script en el contenedor"
  info "  (docker exec -i flexipwn-<env>-attacker bash -s < containment_check.sh)"

# =============================================================================
else
# =============================================================================
# Chequeos de CONTENEDOR: ¿root-en-contenedor se traduce en acceso al host?

  sec "Identidad y mapeo de usuario / rootless (runc escapes CVE-2025-31133/52565/52881)"
  why "Lee uid_map para ver a qué uid del host mapea el root del contenedor."
  why "Si mapea a un uid no-cero (rootless), un escape de runc queda como usuario sin privilegios del host; si mapea a 0, ese mismo escape sería root del host."
  id 2>/dev/null | sed 's/^/  /'
  if [ -r /proc/self/uid_map ]; then
    info "uid_map: $(tr -s ' ' < /proc/self/uid_map | sed 's/^ *//')"
    HOSTUID="$(awk 'NR==1{print $2}' /proc/self/uid_map)"
    if [ "${HOSTUID:-0}" != "0" ]; then
      contained "root del contenedor mapea al uid ${HOSTUID} del host (rootless): un escape NO seria root del host"
    else
      leak "root del contenedor mapea al uid 0 del host (rootful): un escape SERIA root del host"
    fi
  else
    info "No se pudo leer /proc/self/uid_map"
  fi

  sec "Capabilities efectivas (CVE-2025-52881)"
  why "Inspecciona las capabilities del proceso, en especial CAP_SYS_ADMIN."
  why "Sin SYS_ADMIN no se puede montar filesystems ni escribir core_pattern/release_agent, que son la palanca de la mayoría de escapes (incluido el procfs de CVE-2025-52881)."
  CAPEFF="$(awk '/CapEff/{print $2}' /proc/self/status 2>/dev/null)"
  info "CapEff: 0x${CAPEFF:-?}"
  if command -v capsh >/dev/null 2>&1 && [ -n "${CAPEFF:-}" ]; then
    DEC="$(capsh --decode=0x"$CAPEFF" 2>/dev/null)"
    info "${DEC}"
    if echo "$DEC" | grep -qi sys_admin; then
      leak "CAP_SYS_ADMIN presente (habilita mount, core_pattern, release_agent...)"
    else
      contained "sin CAP_SYS_ADMIN"
    fi
  else
    info "capsh no disponible: revisar CapEff a mano (bit 21 = CAP_SYS_ADMIN). Default Docker = 0xa80425fb (sin SYS_ADMIN)."
  fi

  sec "Superficie AF_ALG (Copy Fail / CVE-2026-31431)"
  why "Intenta abrir un socket AF_ALG, la interfaz de cifrado del kernel."
  why "El PoC de Copy Fail necesita ese socket para el bug en algif_aead; si el seccomp por defecto deniega la syscall, el exploit ni siquiera arranca desde el contenedor."
  ALG="INDETERMINADO"
  if command -v python3 >/dev/null 2>&1; then
    ALG="$(python3 -c 'import socket
try:
    s = socket.socket(38, 5, 0)   # AF_ALG, SOCK_SEQPACKET
    s.close(); print("PERMITIDO")
except Exception:
    print("DENEGADO")' 2>/dev/null)"
  elif command -v perl >/dev/null 2>&1; then
    ALG="$(perl -e 'socket(S,38,5,0) or do { print "DENEGADO\n"; exit }; print "PERMITIDO\n"' 2>/dev/null)"
  fi
  case "$ALG" in
    *DENEGADO*)  contained "socket(AF_ALG) denegado por seccomp (superficie de Copy Fail cerrada)" ;;
    *PERMITIDO*) leak "socket(AF_ALG) PERMITIDO (superficie de Copy Fail abierta desde el contenedor)" ;;
    *)           info "AF_ALG indeterminado (instala python3 o perl en la imagen)" ;;
  esac

  sec "core_pattern (CVE-2025-52881 y escape clasico)"
  why "Comprueba (con una reescritura inocua del mismo valor) si core_pattern es modificable desde el contenedor."
  why "Ese archivo define qué binario corre el kernel cuando un proceso crashea, así que escribirlo da ejecución como root del host: es el objetivo de CVE-2025-52881 y de escapes clásicos."
  CUR="$(cat /proc/sys/kernel/core_pattern 2>/dev/null)"
  if { printf '%s' "$CUR" > /proc/sys/kernel/core_pattern; } 2>/dev/null; then
    leak "/proc/sys/kernel/core_pattern es ESCRIBIBLE (vector de escape al host)"
  else
    contained "/proc/sys/kernel/core_pattern no escribible"
  fi

  sec "/proc/sysrq-trigger (CVE-2025-52881 / DoS del host)"
  why "Consulta si /proc/sysrq-trigger es escribible (sin escribir, para no arriesgar el host)."
  why "Escribir ahí dispara acciones del kernel como reboot o kill, de modo que un contenedor con ese acceso podría provocar un DoS del host."
  if [ -w /proc/sysrq-trigger ]; then
    leak "/proc/sysrq-trigger marcado escribible (potencial DoS del host)"
  else
    contained "/proc/sysrq-trigger no escribible"
  fi
fi

# -----------------------------------------------------------------------------
sec "Resumen"
echo "  ${PASS} contenido(s), ${FAIL} fuga(s)."
if [ "$FAIL" -eq 0 ]; then
  if [ "$MODE" = "host" ]; then
    printf '  %s=> Runtime del host endurecido (rootless + runc parcheado).%s\n' "$G" "$N"
  else
    printf '  %s=> El contenedor NO otorga acceso al host (contenido).%s\n' "$G" "$N"
  fi
else
  printf '  %s=> Hay %s hallazgo(s) de fuga/postura: revisar arriba.%s\n' "$R" "$FAIL" "$N"
fi
exit 0
