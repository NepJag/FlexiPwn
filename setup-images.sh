IMAGES=(
  "docker/attacker:flexipwn/attacker"
  "docker/privesc:flexipwn/vuln-sudo"
  "docker/sqli-mysql:flexipwn/vuln-sqli-mysql"
  "docker/vuln-command-injection:flexipwn/vuln-command-injection"
)
 
echo "==> FlexiPwn: construyendo ${#IMAGES[@]} imágenes desde $REPO_ROOT"
echo
 
for entry in "${IMAGES[@]}"; do
  context="${entry%%:*}"
  tag="${entry#*:}"
 
  if [[ ! -d "$context" ]]; then
    echo "ERROR: no existe el contexto de build '$context'" >&2
    exit 1
  fi
 
  echo "==> [$tag]  <-  $context/"
  docker build "$@" -t "$tag" "$context"
  echo
done
 
echo "==> Listo. Imágenes construidas:"
docker images --filter=reference='flexipwn/*' \
  --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}'
 
