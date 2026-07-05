## Playbook: Scan d'image conteneur (Grype)

### Quand ça arrive
- ScanType CONTAINER, outil `grype` sur l'image Docker construite depuis le dépôt.
- Le finding donne un paquet + version + CVE, et souvent le type (`apk`, `deb`, `rpm`, `npm`, `java-archive`, `python`…).

### Étape 1 — Identifier la COUCHE d'origine (ça détermine tout le correctif)
| Type de paquet | Origine | Correctif |
|---|---|---|
| `apk` / `deb` / `rpm` | **Image de base ou paquets OS** | Monter le tag de l'image `FROM`, ou upgrade des paquets dans le Dockerfile |
| `npm` / `java-archive` / `python` / `gobinary` | **Dépendances applicatives embarquées** | Corriger dans le DÉPÔT (manifest + lockfile — démarche SCA), pas dans le Dockerfile |
| binaire dans l'image | Outil installé manuellement | Monter la version téléchargée dans le Dockerfile |

### Étape 2 — Correctifs

**Image de base (le levier n°1)** : la majorité des CVE viennent d'une base vieillissante.
```dockerfile
# Avant
FROM node:18
# Après : version récente + variante slim/alpine (surface réduite)
FROM node:20.11-alpine
```
Encore mieux quand c'est possible : images **distroless** ou multi-stage (le stage final ne contient que le runtime) — élimine des dizaines de CVE d'un coup.

**Paquets OS** : upgrade dans le même `RUN` que l'update :
```dockerfile
RUN apk upgrade --no-cache
# ou (Debian/Ubuntu)
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
```

**Dépendances applicatives** : le Dockerfile n'est pas en cause — mettre à jour la dépendance dans le code source (npm/maven/pip/… selon PIPELINE_CONTEXT), rebuild, et l'image héritera du correctif.

### Étape 3 — Rebuild + re-scan local
```bash
docker build -t app-image:test .
grype app-image:test --only-fixed
```
`--only-fixed` filtre le bruit : n'affiche que ce qui a un correctif disponible.

### Étape 4 — Commit/push (Dockerfile et/ou manifests), puis relancer l'analyse depuis la plateforme.

### Notes
- CVE sans version corrigée dans la distro (fréquent sur Alpine/Debian stable) : souvent non-actionnable immédiatement — vérifier si le paquet est réellement utilisé par l'app, sinon le retirer de l'image ; documenter le reste.
- Multi-stage : les CVE des stages de build (compilateurs, outils) ne sont pas dans l'image finale — vérifier que Grype scanne bien l'image finale.
- Épingler la base par tag précis (voire digest `@sha256:...`) rend les scans reproductibles.
