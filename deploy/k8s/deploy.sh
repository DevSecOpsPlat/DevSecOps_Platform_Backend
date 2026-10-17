#!/usr/bin/env bash
# Déploiement / redéploiement de la plateforme EnviroTest dans le cluster k3s, depuis le PC (Git Bash).
# Images : registry GitLab du projet EnviroTest. Accès cluster : K8S_API_URL + K8S_TOKEN du .env
# (aucun kubeconfig à installer). Le .env lu est DevSecOps_Platform_Frontend/.env, comme docker-compose.
#
#   ./deploy.sh all        build + push backend et frontend, puis applique tout
#   ./deploy.sh backend    rebuild + redéploie le backend seul
#   ./deploy.sh frontend   rebuild + redéploie le frontend seul
#   ./deploy.sh apply      ré-applique manifests + secrets (après une modif du .env), sans rebuild
#   ./deploy.sh stop       arrête frontend + backend (la base et ses données restent)
#   ./deploy.sh start      redémarre frontend + backend
#   ./deploy.sh status     état des pods / services / ingress
#   ./deploy.sh logs       logs du backend en continu (Ctrl+C pour quitter)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BACK_DIR="$(cd "$HERE/../.." && pwd)"
FRONT_DIR="$(cd "$BACK_DIR/../DevSecOps_Platform_Frontend" && pwd)"
ENV_FILE="${ENV_FILE:-$FRONT_DIR/.env}"
REGISTRY="registry.gitlab.com/amanibennaceur-group/envirotest"
NS=envirotest
# IP VMnet8 du PC (SonarQube, DefectDojo, Ollama en Docker) : fixe, attribuée par VMware.
# C'est le seul endroit à modifier si elle devait changer.
PC_IP="${PC_IP:-192.168.92.1}"

env_value() { tr -d '\r' < "$ENV_FILE" | grep -E "^$1=" | head -1 | cut -d= -f2-; }

K8S_API_URL="$(env_value K8S_API_URL)"
K8S_TOKEN="$(env_value K8S_TOKEN)"
if [ -z "$K8S_API_URL" ] || [ -z "$K8S_TOKEN" ]; then
  echo "K8S_API_URL / K8S_TOKEN absents de $ENV_FILE" >&2
  exit 1
fi

# Certificat de l'autorité du cluster (public) : le certificat de l'API est vérifié normalement.
CA_FILE="$HERE/k3s-server-ca.crt"
if command -v cygpath >/dev/null 2>&1; then CA_FILE="$(cygpath -m "$CA_FILE")"; fi

# KUBECONFIG inexistant : on n'hérite pas du contexte docker-desktop éventuel du PC.
kc() {
  KUBECONFIG="$HERE/.kubeconfig-inexistant" kubectl --server="$K8S_API_URL" --token="$K8S_TOKEN" \
    --certificate-authority="$CA_FILE" "$@"
}

# Build + push d'une image ; seule la référence de l'image sort sur stdout.
build_push() {
  local svc="$1" dir args=() tag img
  if [ "$svc" = backend ]; then
    dir="$BACK_DIR"
  else
    dir="$FRONT_DIR"
    args=(--build-arg ANGULAR_CONFIG=docker)
  fi
  tag="$(git -C "$dir" rev-parse --short HEAD)"
  if [ -n "$(git -C "$dir" status --porcelain --untracked-files=no)" ]; then
    tag="$tag-local-$(date +%Y%m%d%H%M)"
    echo "Attention : $svc contient des modifications non commitées (tag $tag)" >&2
  fi
  img="$REGISTRY/platform-$svc:$tag"
  docker build "${args[@]}" -t "$img" "$dir" >&2
  docker push "$img" >&2
  echo "$img"
}

current_image() {
  kc -n "$NS" get deploy "$1" -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || true
}

apply_secrets() {
  kc apply -f - < "$HERE/00-namespace.yaml"
  # .env -> Secret envirotest-backend-env (commentaires et fins de ligne Windows ignorés)
  {
    printf 'apiVersion: v1\nkind: Secret\nmetadata:\n  name: envirotest-backend-env\n  namespace: %s\ntype: Opaque\ndata:\n' "$NS"
    tr -d '\r' < "$ENV_FILE" | grep -E '^[A-Za-z_][A-Za-z0-9_]*=' | while IFS= read -r line; do
      printf '  %s: %s\n' "${line%%=*}" "$(printf '%s' "${line#*=}" | base64 -w0)"
    done
  } | kc apply -f -
  kc -n "$NS" create secret docker-registry gitlab-registry --docker-server=registry.gitlab.com \
    --docker-username=oauth2 --docker-password="$(env_value GITLAB_TOKEN)" \
    --dry-run=client -o yaml | kc apply -f -
  # Mot de passe de la base : généré une seule fois, jamais régénéré (la base l'a déjà enregistré)
  if ! kc -n "$NS" get secret envirotest-db >/dev/null 2>&1; then
    kc -n "$NS" create secret generic envirotest-db --from-literal=password="$(openssl rand -hex 24)"
  fi
}

apply_manifests() {
  local f
  for f in "$HERE"/[0-9]*.yaml; do
    echo '---'
    sed -e "s|__BACKEND_IMAGE__|$BACKEND_IMAGE|g" \
        -e "s|__FRONTEND_IMAGE__|$FRONTEND_IMAGE|g" \
        -e "s|__PC_IP__|$PC_IP|g" "$f"
  done | kc apply -f -
}

rollout() {
  local d
  for d in "$@"; do
    kc -n "$NS" rollout status "deploy/$d" --timeout=420s
  done
}

case "${1:-}" in
  all)
    BACKEND_IMAGE="$(build_push backend)"
    FRONTEND_IMAGE="$(build_push frontend)"
    apply_secrets
    apply_manifests
    rollout backend frontend
    ;;
  backend|frontend)
    img="$(build_push "$1")"
    kc -n "$NS" set image "deploy/$1" "$1=$img"
    rollout "$1"
    ;;
  apply)
    BACKEND_IMAGE="$(current_image backend)"
    FRONTEND_IMAGE="$(current_image frontend)"
    if [ -z "$BACKEND_IMAGE" ] || [ -z "$FRONTEND_IMAGE" ]; then
      echo "Aucune image déployée : lancer d'abord ./deploy.sh all" >&2
      exit 1
    fi
    apply_secrets
    apply_manifests
    # Un Secret modifié ne redémarre pas le pod tout seul : on force la relecture du .env
    kc -n "$NS" rollout restart deploy/backend
    rollout backend frontend
    ;;
  stop)
    kc -n "$NS" scale deploy/backend deploy/frontend --replicas=0
    ;;
  start)
    kc -n "$NS" scale deploy/backend deploy/frontend --replicas=1
    rollout backend frontend
    ;;
  status)
    kc -n "$NS" get pods,svc,ingress,pvc -o wide
    ;;
  logs)
    kc -n "$NS" logs deploy/backend --tail=200 -f
    ;;
  *)
    sed -n '2,13p' "$0"
    exit 1
    ;;
esac
