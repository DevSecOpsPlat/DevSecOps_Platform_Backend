## Playbook: Lint Dockerfile (Hadolint)

### Quand ça arrive
- Outil : `hadolint` sur le `Dockerfile` du dépôt.
- Findings identifiés par un code de règle `DLxxxx` (Hadolint) ou `SCxxxx` (ShellCheck intégré).

### Règles fréquentes et correctifs
1) **DL3006 / DL3007** — image de base sans tag ou en `:latest` :
   - Épingler une version précise : `FROM node:20.11-alpine` au lieu de `FROM node` ou `FROM node:latest`.
2) **DL3008 / DL3018** — packages non épinglés (`apt-get install x` / `apk add x`) :
   - Épingler : `apt-get install -y curl=8.5.0-2ubuntu10` ou `apk add --no-cache curl=8.5.0-r0` (adapter à la version dispo dans l'image de base).
3) **DL3002 / manque de `USER`** — le conteneur tourne en root :
   - Créer un utilisateur non-root et l'utiliser : `RUN adduser -D appuser` puis `USER appuser` avant `CMD`.
4) **DL3009 / DL3015** — caches non nettoyés / paquets recommandés :
   - `apt-get update && apt-get install -y --no-install-recommends ... && rm -rf /var/lib/apt/lists/*` dans le **même** `RUN`.
5) **DL3020 / DL3025** — `ADD` au lieu de `COPY`, `CMD` en forme shell :
   - Préférer `COPY` et la forme exec `CMD ["node", "server.js"]`.

### Étapes
1) Ouvrir le `Dockerfile` à la ligne indiquée par le finding.
2) Lire la règle (le code DLxxxx est documenté sur le wiki Hadolint) et appliquer le correctif minimal ci-dessus.
3) Rebuild local pour vérifier que l'image se construit toujours.
4) Commit/push puis relancer l'analyse depuis la plateforme.

### Vérification locale
```bash
hadolint Dockerfile
docker build -t app-image:test .
```

### Notes
- Ces findings sont de la **qualité/durcissement d'image**, rarement des vulnérabilités exploitables directement — mais `USER root` et `:latest` ont un vrai impact sécurité (surface d'attaque, builds non reproductibles).
- Épingler l'image de base réduit aussi les surprises côté scan Grype.
