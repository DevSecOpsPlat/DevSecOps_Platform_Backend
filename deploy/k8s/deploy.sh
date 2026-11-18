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
  docker build "${args[@]}" -t "$img" "$dir" >&2 || return 1
  # Le registre GitLab renvoie parfois une erreur passagère sur une couche : on réessaie.
  # « return 1 » explicite : set -e ne s'applique PAS dans une substitution $(...) — sans lui, un
  # envoi raté laissait le script appliquer une image absente du registre (backend arrêté le 17/11/2026).
  local n
  for n in 1 2 3; do
    docker push "$img" >&2 && break
    if [ "$n" = 3 ]; then return 1; fi
    echo "Envoi de $img : nouvel essai ($n/3)…" >&2
    sleep 5
  done
  echo "$img"
}

# Télécharge l'image du backend sur son nœud AVANT de basculer : le backend est en « Recreate »
# (volume RWO), l'ancien pod s'arrête dès l'application. Sans ce préchargement, la plateforme
# restait coupée pendant tout le téléchargement (~13 min avec la connexion actuelle).
prepull() {
  local img="$1" node pod="prepull-$(date +%s)" phase reason i failures=0
  node="$(kc -n "$NS" get pod -l app=backend -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null || true)"
  [ -n "$node" ] || return 0
  echo "Préchargement de $img sur $node (l'ancien backend reste en ligne)…" >&2
  kc -n "$NS" run "$pod" --image="$img" --restart=Never \
    --overrides="{\"apiVersion\":\"v1\",\"spec\":{\"nodeName\":\"$node\",\"imagePullSecrets\":[{\"name\":\"gitlab-registry\"}]}}" \
    --command -- sh -c 'exit 0' >/dev/null || return 1
  for i in $(seq 1 180); do
    phase="$(kc -n "$NS" get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    case "$phase" in Succeeded|Failed) break ;; esac
    reason="$(kc -n "$NS" get pod "$pod" -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null || true)"
    case "$reason" in
      ErrImagePull|ImagePullBackOff|InvalidImageName)
        # Une erreur passagère de téléchargement est réessayée par Kubernetes : on n'abandonne
        # qu'après plusieurs constats (image réellement absente ou nom invalide).
        failures=$((failures + 1))
        if [ "$reason" = InvalidImageName ] || [ "$failures" -ge 12 ]; then
          echo "Préchargement impossible ($reason) — rien n'est appliqué." >&2
          kc -n "$NS" delete pod "$pod" --wait=false >/dev/null 2>&1 || true
          return 1
        fi ;;
    esac
    sleep 10
  done
  kc -n "$NS" delete pod "$pod" --wait=false >/dev/null 2>&1 || true
  echo "Image préchargée sur $node." >&2
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
    BACKEND_IMAGE="$(build_push backend)" || { echo "Image backend non envoyée — aucun changement appliqué." >&2; exit 1; }
    FRONTEND_IMAGE="$(build_push frontend)" || { echo "Image frontend non envoyée — aucun changement appliqué." >&2; exit 1; }
    prepull "$BACKEND_IMAGE" || exit 1
    apply_secrets
    apply_manifests
    rollout backend frontend
    ;;
  backend|frontend)
    img="$(build_push "$1")" || { echo "Image $1 non envoyée — aucun changement appliqué." >&2; exit 1; }
    if [ "$1" = backend ]; then prepull "$img" || exit 1; fi
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
