# Déploiement de la plateforme dans le cluster k3s

## Qui tourne où

| Où | Quoi |
|---|---|
| Cluster k3s, namespace `envirotest` | frontend, backend, PostgreSQL de la plateforme |
| Cluster k3s, namespaces `env-*` | les applications déployées **par** la plateforme |
| PC Windows (Docker) | SonarQube `:9000`, DefectDojo `:8080`, Ollama `:11434` (secours IA), GitLab Runner |

Routage public (aucune configuration Hostinger/Cloudflare nécessaire) :

```
https://envirotest.cloud      ─┐
https://api.envirotest.cloud  ─┼─ Cloudflare ─ tunnel (cloudflared, ns default) ─ Traefik ─ Ingress
https://<app>.envirotest.cloud ┘
  envirotest.cloud      → frontend (son nginx proxifie /projet/ → backend:8089)
  api.envirotest.cloud  → backend:8089   (rappels des pipelines GitLab)
  <app>.envirotest.cloud → Ingress générés par la plateforme dans les namespaces env-*
```

Le backend joint les outils du PC via `192.168.92.1` (carte VMware VMnet8 du PC, fixe — pas l'IP
Wi-Fi). Les URLs du `.env` (`host.docker.internal`, `ollama`) sont résolues vers cette IP par
`hostAliases` (20-backend.yaml) ; elles restent valables pour les jobs du runner sur le PC.

## Au quotidien

Depuis Git Bash, dans ce dossier :

```bash
./deploy.sh backend     # après une modif du backend (build + push + redéploiement)
./deploy.sh frontend    # après une modif du frontend
./deploy.sh all         # les deux
./deploy.sh apply       # après une modif du .env (DevSecOps_Platform_Frontend/.env)
./deploy.sh stop        # arrêter la plateforme (la base reste)
./deploy.sh start       # la relancer
./deploy.sh status      # état
./deploy.sh logs        # logs du backend
```

Le tag d'image est le commit courant (`git rev-parse --short HEAD`) ; s'il reste des modifications
non commitées, elles sont incluses et le tag reçoit le suffixe `-local-<date>`.

## Configuration

- Le code garde ses valeurs par défaut `localhost` (développement local inchangé).
- Les valeurs propres au cluster (domaine, URL de rappel, base) sont dans le bloc `env:` de
  `20-backend.yaml` et l'emportent sur le `.env`.
- `k3s-server-ca.crt` : certificat public de l'autorité du cluster, pour que `kubectl` vérifie le
  certificat de l'API (valable jusqu'en 2036). Ce n'est pas un secret.
- Les secrets ne sont jamais committés : `deploy.sh` crée `envirotest-backend-env` depuis le `.env`,
  `gitlab-registry` (pull des images) et `envirotest-db` (mot de passe de la base, généré une fois).

## Retour à l'ancien mode Docker (si besoin)

1. `./deploy.sh stop`
2. `docker start envirotest-postgres envirotest-backend envirotest-frontend`
3. Ré-appliquer l'ancien routage : `/home/master/Desktop/envirotest-routing.yaml` sur le master,
   après avoir supprimé l'Ingress `envirotest-platform` du namespace `envirotest`.

Attention : les données écrites dans la base du cluster depuis la bascule ne sont pas dans
l'ancienne base Docker.
