# Audit — Module Déploiement (EnviroTest)

> Référence interne. Cartographie technique + analyse des manques du flux **Déploiement**
> uniquement (création du service → dashboard → Runtime & Environments). Le Scan
> (SonarQube, DefectDojo) fait partie du même pipeline/dashboard mais reste hors périmètre —
> traité séparément. Rédigé à partir d'une lecture directe du code (aucune modification lors
> de l'audit). Date : 15 août 2026.

## Sommaire

1. [Cartographie technique du flux Déploiement](#1-cartographie-technique-du-flux-déploiement)
2. [Fonctionnalités déjà en place](#2-fonctionnalités-déjà-en-place-non-documentées-ailleurs)
3. [Technologies rencontrées](#3-technologies-rencontrées)
4. [Analyse des manques par interface](#4-analyse-des-manques--point-de-vue-utilisateur)
5. [Récapitulatif priorisé](#5-récapitulatif-priorisé)

---

## 1. Cartographie technique du flux Déploiement

Le clic « Déployer » n'est **pas synchrone**. Le backend répond immédiatement
(`202 Accepted` côté sens propre, matérialisé par un message « apply Kubernetes en cours »)
et fait le vrai travail en tâche de fond ; c'est le job GitLab qui revient sonder l'état
jusqu'à ce que les pods soient prêts.

```
Angular UI (project-deploy-modal, clic Déployer)
   │  POST /api/managed-applications/{id}/deploy
   ▼
Spring · ApplicationManagementService.deploy() → AppDeploymentService.deploy()
   │  valide (AppDeploymentValidationService) → calcule les vagues (BD → deps → indépendants)
   │  crée AppDeployment (namespace stable env-<slug>-<id8>) + EphemeralEnvironment (TTL)
   │  déclenche le pipeline GitLab (variables CI : repo, branche, namespace, TTL, secret…)
   ▼
Pipeline GitLab · ACTION=deploy
   clone → build (docker/kaniko/host) → grype-scan (image, résultat non affiché)
   → push-image → deploy:trigger-backend
   │  POST BACKEND_URL/api/deploy  { image(s), namespace, deploymentId, environmentId }
   ▼
Spring · EnvironmentController /api/deploy → AppDeploymentService.scheduleCiDeploy()
   │  répond tout de suite (deploying) puis lance executeCiDeployWork() en async (pool 4)
   ▼
Cluster K8s — via Fabric8 (K8sManifestApplyService)
   1. namespace + ResourceQuota (cpu/mem, défaut 4 / 8Gi) + imagePullSecret (registry privé)
   2. apply bundle BD → waitUntilDatabasesReady()
   3. pour chaque vague de services : apply → scaleDeployment() explicite (SSA ignore souvent
      spec.replicas) → waitUntilNamedDeploymentsReady()
   4. Ingress + Middleware (Traefik) — appliqués APRÈS readiness, soft-fail (URL indisponible
      ≠ échec du déploiement)
   ▲
   │  le job deploy:trigger-backend boucle GET /api/deploy/status/{id} — jusqu'à 30×10s
   │
Spring · AppDeploymentService.getCiDeployStatus()
   │  pods attendus Ready ? → status = RUNNING, EnvironmentLifecycleService.onReady()
   │  démarre l'horloge TTL, résout l'URL publique
   ▼
Angular UI — consommation : Dashboard (URL, bandeau env actif) · Runtime & Environments
   (détail, TTL) · Monitoring (poll 15s) · Alertes (poll 10s, capture immédiate en historique)
```

### Étape par étape — couche moteur / couche utilisateur

#### 1. Création du service

- **Moteur** : `ApplicationManagementService.addService()` persiste `AppService` (rôle
  FRONTEND/BACKEND/WORKER, requests/limits CPU/mem, replicas, dépendance service et/ou base)
  et ses `ServiceEnvVar`. Secrets chiffrés au repos. Aucun appel cluster à cette étape.
- **Utilisateur** : `service-form.component` — repo/branche, Dockerfile, port, « dépend de »,
  variables d'env (case « secret »). Pas de validation de ressources visible ici.

#### 2. Clic « Déployer »

- **Moteur** : `AppDeploymentValidationService.validate()` bloque les incohérences (backend
  sans BD dans l'app, référence cross-app…) ; `preview()` renvoie infos/warnings/erreurs
  bloquantes avant confirmation. `AppDeploymentService.deploy()` crée l'`AppDeployment`
  (namespace stable via son id), calcule les vagues (tri en 3 paliers bornés : BD → services
  dépendants → services indépendants), génère le bundle YAML des bases, crée
  l'`EphemeralEnvironment` porteur du TTL, déclenche le pipeline GitLab.
- **Utilisateur** : `project-deploy-modal` — branche, TTL (1–72h), domaine personnalisé
  optionnel, cases à cocher par service (bases liées incluses automatiquement). Aperçu live
  (debounce 250ms) : infos / warnings / erreurs bloquantes, confirmation explicite si
  persistance absente.

#### 3. Écran détail du pipeline

- **Moteur** : pipeline unique `.gitlab-ci.yml` routé par `ACTION` (jobs `deploy:*`
  uniquement si `ACTION=deploy`). Stages : `clone → build → grype-scan → push-image →
  deploy-k8s (trigger-backend)`. `deploy:trigger-backend` POST `/api/deploy` (secret
  `X-Pipeline-Secret`) puis boucle `GET /api/deploy/status/{id}` (30×10s) — le job ne passe
  vert que si le cluster confirme les pods Ready.
- **Utilisateur** : `pipeline-details.component` (page dédiée) ou vue inline dans Runtime —
  Stages & Jobs, détail job + logs, bouton « relancer les jobs échoués du stage », assistant
  IA sur les logs. Pas de retour fin sur ce qui se passe *dans* le job trigger-backend
  pendant qu'il boucle.

#### 4. Fin de déploiement

- **Moteur** : `K8sManifestApplyService` (Fabric8) — `applyManifests()` (Server-Side Apply),
  `waitUntilDatabasesReady()`, `waitUntilNamedDeploymentsReady()` par vague,
  `scaleDeployment()` explicite. Ingress/Middleware en soft-fail après readiness.
  `getCiDeployStatus()` bascule `RUNNING` dès que les workloads attendus sont prêts, puis
  `EnvironmentLifecycleService.onReady()` démarre le TTL. Détection d'alertes runtime : scan
  planifié (2 min) **et**, depuis cette session, capture immédiate à chaque consultation live
  de l'onglet Alertes.
- **Utilisateur** : le job GitLab passe vert, `SUCCESS` affiché. Aucun résumé « qu'est-ce qui
  vient d'être déployé » sur cette même page — il faut changer d'onglet vers Runtime.

#### 5. Remplissage du dashboard

- **Moteur** : `AppConnectionUrlService` génère l'URL de connexion BD (DNS interne
  `db-<name>.<namespace>.svc`), stockée chiffrée, masquée avec endpoint « révéler ». URL
  publique résolue via l'Ingress (nip.io par défaut, ou domaine personnalisé), stockée sur
  l'`EphemeralEnvironment`.
- **Utilisateur** : Dashboard Overview → bloc « Environnement actif » (bandeau) : URL,
  statut, aperçu iframe, TTL. Aucun graphique ni historique visuel sur cette page.

#### 6. Dashboard Monitoring

- **Moteur** : `K8sManifestApplyService.getNamespaceMonitoring()` agrège metrics-server
  (CPU/mem), API kubelet (network/disk), `fetchResourceQuotaStatus()` (hard vs used du
  `ResourceQuota` namespace), événements K8s récents.
- **Utilisateur** : `monitoring-dashboard.component` — CPU/mem/réseau/disque par pod, jauges
  de quota namespace, workloads, services K8s, événements, logs. Rafraîchi 15s.
- **Jugé suffisant, non remis en question dans cet audit.** Seule observation transverse : la
  jauge de quota qu'il calcule n'est visible que là, alors qu'elle expliquerait directement
  des incidents vus ailleurs (Runtime, Alertes).

#### 7. Runtime & Environments

- **Moteur** : `DeploymentStatusComponent` (« full ») — onglets Pipeline / Services / Bases /
  Pods / Connexions, polling ciblé (pods 10s, pipeline CI 5s tant qu'actif).
  `ManagedAppHistoryComponent` fusionne déploiements + lots de scan en timeline filtrable.
  `DeploymentRuntimeAlertService` — alertes live + historique persisté (`Alert`, dédup 30
  min), filtrable environnement + date (session en cours).
- **Utilisateur** : TTL avec extension (+1h/+2h/+4h, plafond 72h depuis Ready), aperçu
  iframe, logs par pod/service/base, secrets révélables. Un environnement `STOPPED` garde son
  pipeline et ses services consultables ; seuls les pods (réellement détruits) affichent un
  message dédié.

---

## 2. Fonctionnalités déjà en place (non documentées ailleurs)

| Fonctionnalité | Détail |
|---|---|
| **TTL à deux temps** | Expiration logique (check 60s) puis nettoyage physique du namespace (check 120s) — le statut UI bascule avant que le cluster ait fini de nettoyer. |
| **Sync runtime sans rebuild CI** | `syncServiceRuntime()` ré-applique le manifeste (env vars, ressources…) et redémarre le Deployment directement via Fabric8, sans repasser par la CI. Déclenché automatiquement après chaque édition de service — **mais ne crée aucune trace dans l'historique des déploiements.** |
| **Rebuild ciblé d'un service** | `deploySingleService()` relance un seul service (+ sa BD dépendante) dans le même namespace. |
| **Teardown à deux voies** | Suppression directe du namespace via Fabric8 si le cluster est configuré, sinon repli sur un job pipeline dédié (`ACTION=teardown`). |
| **Isolation multi-utilisateur** | 1 namespace K8s par déploiement (pas par application) + `ResourceQuota` (4 CPU / 8Gi par défaut) + `imagePullSecret` dédié — la frontière de tenant est le namespace. |
| **Alertes runtime persistées** | CrashLoop, OOM, health check KO, warnings K8s — capturées en live à chaque poll de l'onglet (10s) et par un scan planifié (2 min) de secours, dédupliquées 30 min, historique filtrable par environnement et date. |
| **Secrets révélables à la demande** | Mots de passe BD masqués par défaut, endpoint séparé de révélation. |
| **Assistant IA sur les logs pipeline** | Explique un échec de job ou répond à une question libre, contexte projet injecté côté backend. |

**Point mineur signalé en passant** : le pipeline de déploiement inclut un scan de l'image
construite (`deploy:grype-scan`, Grype) — distinct du module Scan complet. Son résultat
(CRITICAL/HIGH) est calculé et loggé en CI mais **n'est affiché nulle part sur la
plateforme**. Traitement avec le module Scan, hors périmètre ici.

---

## 3. Technologies rencontrées

| Techno | Rôle |
|---|---|
| Fabric8 Kubernetes Client | Seul point de contact avec le cluster — apply, wait-ready, scale, quota, events, delete namespace |
| Spring Boot 3 + Hibernate/PostgreSQL | Backend, persistance applications/services/déploiements/alertes |
| GitLab CI (API-triggered) | Pipeline unique multi-stage, routé par variable `ACTION` |
| Traefik (Ingress + Middleware) | Exposition publique, appliqué en soft-fail après readiness |
| metrics-server + kubelet summary API | Source des métriques CPU/mem/réseau/disque du Monitoring |
| Docker-in-Docker / Kaniko | Build d'image, bascule selon config runner |
| Grype | Scan de l'image construite en pipeline déploiement (résultat non exposé) |
| Angular standalone + RxJS | Frontend, polling ciblé par onglet |
| Chart.js | Graphiques du Monitoring dashboard |

---

## 4. Analyse des manques — point de vue utilisateur

Minimum attendu à chaque étape pour quelqu'un qui déploie pour la première fois : *qu'est-ce
qui va être déployé et à quel coût en ressources*, *où en est-on pendant que ça tourne*,
*qu'est-ce qui vient de se passer une fois fini*, *est-ce que je peux revoir ce qui s'est
passé plus tard*.

### Dashboard Overview

| Existant | Manque | Suggestion |
|---|---|---|
| Composition (services + bases, CRUD rapide) | Aucun graphique — pas d'historique des déploiements dans le temps | Graphique barres « déploiements 30 derniers jours » (réussi/échec/arrêté) — donnée déjà dispo via `listDeployments` |
| Bandeau « Environnement actif » (URL, TTL, aperçu iframe) | Empreinte ressources jamais confrontée au quota namespace **avant** de confirmer — a laissé passer le dépassement de quota observé cette session | Dans la modale Déployer, sommer les requests CPU/mem des services cochés, afficher à côté du quota namespace connu |
| Modale Déployer avec aperçu (warnings/blocages/infos) | Pas de résumé « dernier événement » sans ouvrir un autre onglet | Carte « Dernier événement », réutilise l'historique d'alertes app-wide |
| Bloc Sécurité & qualité (hors périmètre) | Pas de lien direct vers le pipeline en cours pendant un déploiement | Lien « Voir le pipeline » quand statut = DEPLOYING |

### Vue détail du pipeline

| Existant | Manque | Suggestion |
|---|---|---|
| Stages & Jobs, statut coloré, relance jobs échoués | Aucun équivalent « Résultat du déploiement » (existe pour le scan) | Bloc « Résultat du déploiement » (namespace, URL, services prêts) si kind=DEPLOY + SUCCESS, avec lien « Ouvrir Runtime » |
| Détail job + logs bruts | `deploy:trigger-backend` reste une boîte noire pendant le polling (jusqu'à 5 min) | Exposer la progression fine (BD → vague N → ingress), déjà en transit dans `servicesState` |
| Assistant IA, bloc « Résultat du scan » | Pas de lien direct vers l'environnement Runtime une fois vert | — |

### Dashboard Monitoring

Jugé suffisant — non remis en question dans cet audit. Seule sa donnée de quota est
recommandée en réutilisation ailleurs (Dashboard, Runtime), pas de modification proposée ici.

### Runtime & Environments

| Existant | Manque | Suggestion |
|---|---|---|
| Détail complet même après arrêt (corrigé cette session) | Un sync-runtime modifie l'environnement en direct sans créer d'entrée d'historique | Enregistrer un événement (même léger) à chaque sync-runtime, distinct visuellement d'un vrai redéploiement CI |
| Historique fusionné déploiements + scans, filtrable | Pas de jauge de quota ici — un `FailedCreate` par quota oblige à ouvrir Monitoring | Reprendre la mini-jauge quota du Monitoring dans le panneau Runtime |
| Alertes live + historique filtrable env/date (corrigé cette session) | Le teardown manuel ne rappelle pas le temps déjà consommé avant suppression | Relier un événement quota, dans l'historique, à la jauge concernée d'un clic |
| TTL avec extension, rebuild ciblé, secrets révélables | | |

---

## 5. Récapitulatif priorisé

### Quick wins — donnée déjà calculée

| # | Item | Statut |
|---|---|---|
| 1 | Jauge de quota namespace dans Runtime | ✅ fait |
| 2 | Carte « dernier événement » sur le Dashboard | ✅ fait |
| 3 | Empreinte ressources dans la modale Déployer | ✅ fait |
| 4 | Bannière « résultat du déploiement » sur la page pipeline | ✅ fait |

### Chantiers moyens — un peu de backend

| # | Item | Statut |
|---|---|---|
| 5 | Traçabilité des sync-runtime | ✅ fait |
| 6 | Progression fine pendant le polling pipeline | ✅ fait |
| 7 | Graphique « déploiements dans le temps » sur le Dashboard | ✅ fait |

**Détail de l'implémentation** (backend + frontend, déployé et vérifié en local le 15 août 2026) :

1. **Quota Runtime** : `DeploymentStatusComponent` lit désormais `res.quota` (déjà calculé par `K8sManifestApplyService.getNamespaceMonitoring()`) et affiche une puce CPU/MEM dans le bandeau santé.
2. **Dernier événement (Dashboard)** : nouvelle carte alimentée par `getAppAlertsHistory()` (premier élément de l'historique, déjà trié par date).
3. **Empreinte ressources (modale Déployer)** : `DeployPreviewResponse` expose désormais `requestedCpuMillicores`/`requestedMemoryBytes` (somme des requests des services cochés) vs `quotaCpuMillicores`/`quotaMemoryBytes` (config namespace), avec avertissement automatique si dépassement — calculé dans `AppDeploymentValidationService.preview()`, réutilise les parseurs `K8sManifestApplyService.parseCpuToCores/parseMemoryToBytes` (rendus package-visible).
4. **Résultat du déploiement (pipeline)** : `pipeline-details.component` résout l'`AppDeployment` correspondant au pipeline (`gitlabPipelineId`) et affiche namespace/URL/services prêts une fois terminé, avec lien direct vers Runtime.
5. **Traçabilité sync-runtime** : nouveau type `AlertType.DEPLOYMENT_SYNC_RUNTIME` (sévérité `info`, catégorie `sync`), enregistré sans dédup à chaque `syncServiceRuntime()` réussi — visible dans l'Historique des alertes, distinct visuellement (badge bleu « Sync runtime », pas rouge/orange).
6. **Progression fine pipeline** : nouveau champ `servicesState.deployPhase` mis à jour à chaque étape de l'apply K8s (namespace → BD → vague N/total → ingress), exposé via `getDeployment()`/`getCiDeployStatus()` ; la page pipeline le sonde toutes les 4 s tant que le déploiement est `DEPLOYING`.
7. **Graphique Dashboard** : réutilisation telle quelle de la courbe « Évolution des déploiements » déjà construite pour l'onglet Runtime (`renderEnvHistoryChart`/`buildEnvHistorySeries`, 30 jours, succès/échecs) — juste rendue aussi sur le Dashboard Overview.

### Chantiers longs / hors périmètre — lancés sur demande explicite (15 août 2026)

| # | Item | Statut |
|---|---|---|
| 8 | Tests applicatifs post-déploiement (smoke test) | ✅ fait |
| 9 | Résultat Grype affiché sur la plateforme | ✅ fait (backend + frontend) — ⚠️ un ajout manuel au pipeline reste nécessaire, voir ci-dessous |
| 10 | Notion de « coût temps-machine » cumulé | ✅ fait (proxy approximatif) |

**Détail :**

8. **Smoke test post-déploiement** : dès qu'un environnement passe `RUNNING` pour la première fois, `AppDeploymentService.runSmokeTest()` sonde une fois l'URL publique de chaque service exposé (réutilise le probe HTTP du health check Monitoring, résolution ingress/.local incluse) et stocke `servicesState.smokeTest = { allOk, results }`. Affiché dans la bannière « Résultat du déploiement » de la page pipeline (« Smoke test : 3/3 OK »).

9. **Résultat Grype** : nouvel endpoint `POST /api/webhooks/managed-deployments/{deploymentId}/container-scan` (même secret partagé `X-Pipeline-Secret` que le callback de statut existant), persiste `servicesState.containerScan = { critical, high, medium, low, imageName }`, affiché dans la même bannière pipeline.
   ⚠️ **Non fait délibérément** : je n'ai pas modifié `.gitlab-ci.yml` du dépôt EnviroTest (fichier connecté à un vrai projet GitLab, avec déjà des modifications locales non commitées, et la convention documentée dans `architecture.md` §6 est explicite : « l'utilisateur place ce fichier, l'outil ne l'écrit pas »). À ajouter manuellement dans le job `deploy:grype-scan`, juste après le calcul de `CRIT`/`HIGH` :
   ```yaml
   - |
     CRIT=$(jq '[.matches[]?.vulnerability?.severity? | select(.=="Critical")] | length' reports/container-scan/grype-image.json 2>/dev/null || echo 0)
     HIGH=$(jq '[.matches[]?.vulnerability?.severity? | select(.=="High")] | length' reports/container-scan/grype-image.json 2>/dev/null || echo 0)
     MED=$(jq '[.matches[]?.vulnerability?.severity? | select(.=="Medium")] | length' reports/container-scan/grype-image.json 2>/dev/null || echo 0)
     LOW=$(jq '[.matches[]?.vulnerability?.severity? | select(.=="Low")] | length' reports/container-scan/grype-image.json 2>/dev/null || echo 0)
     echo "Grype: CRITICAL=$CRIT HIGH=$HIGH (gate au stage security-validation)"
     if [ -n "$BACKEND_URL" ] && [ -n "$DEPLOYMENT_ID" ] && [ -n "$PIPELINE_SECRET" ]; then
       curl -s -o /dev/null -X POST "${BACKEND_URL}/api/webhooks/managed-deployments/${DEPLOYMENT_ID}/container-scan" \
         -H "Content-Type: application/json" \
         -H "X-Pipeline-Secret: ${PIPELINE_SECRET}" \
         -d "{\"critical\":${CRIT:-0},\"high\":${HIGH:-0},\"medium\":${MED:-0},\"low\":${LOW:-0},\"imageName\":\"${IMAGE_NAME:-}\"}" || true
     fi
   ```

10. **Temps-machine cumulé** : nouvel endpoint `GET /api/managed-applications/{id}/machine-time`, somme sur tous les déploiements de l'app de la durée `readyAt → arrêt (ou maintenant)`. **Explicitement approximatif** — proxy d'usage, pas une facturation exacte (dit tel quel dans l'UI). Affiché sur le Dashboard Overview, sous le graphique de déploiements.

---

## 6. Addendum — URLs publiques sécurisées (16 août 2026)

Suite à la mise en place d'un domaine réel (`envirotest.cloud`, DNS chez Cloudflare) et d'un **Cloudflare Tunnel** pointant vers `traefik.traefik.svc.cluster.local:80` (routage wildcard `*.envirotest.cloud` inclus), deux correctifs livrés côté plateforme :

- **Domaine personnalisé automatique** : une app **sans** « Domaine personnalisé » explicite obtient désormais automatiquement `<slug-app>.envirotest.cloud` (config `deployment.ingress.custom-base-domain`, vide = comportement d'origine/nip.io inchangé). Le champ du formulaire reste disponible pour un override manuel, mais n'est plus obligatoire. Logique centralisée dans `AppDeploymentService.effectiveCustomHostname()`.
- **Scheme `https://` au lieu de `http://` codé en dur** : les URLs générées pour un hostname personnalisé (auto ou tapé) utilisent maintenant `deployment.ingress.custom-scheme` (défaut `https`) — cohérent avec le fait qu'un domaine perso passe par un tunnel/reverse-proxy qui termine le TLS (Cloudflare Tunnel dans notre cas). Le fallback nip.io garde son propre scheme (`deployment.preview.nip.scheme`, `http` par défaut), inchangé.

**Infrastructure (hors dépôt, sur la VM K3s)** : tunnel Cloudflare `envirotest`, 2 connecteurs `cloudflared` déployés en Deployment K8s (namespace `default`), 4 routes « Published application » (racine + `api`/`sonar`/`dojo`) + 1 route wildcard `*` — toutes vers `traefik.traefik.svc.cluster.local:80`. Config Traefik existante (LoadBalancer via K3s ServiceLB) non modifiée. Ancien bloc ACME/Let's Encrypt via Hostinger abandonné (Cloudflare termine le TLS à sa frontière).

---

## 7. Addendum — Capacité réelle du nœud K8s (17 août 2026)

**Constat soulevé pendant la vérification du chantier #3** : la jauge « Empreinte ressources vs quota namespace » (modale Déployer) et la puce « Quota namespace » (Runtime) ne montrent que le quota **du namespace de l'app** (`ResourceQuota env-quota`, 4 CPU / 8 Gi par défaut). Si un *autre* namespace a déjà consommé une bonne partie de la capacité **physique** du nœud, l'utilisateur voit toujours « 150m / 4.00 cores » — un chiffre confortable — alors que le nœud, lui, n'a peut-être plus rien de libre. Le déploiement passe alors la validation applicative mais le pod reste bloqué `Pending` côté K8s (faute de nœud avec assez de ressources allocatables), sans que rien dans l'UI ne l'ait annoncé.

Le quota namespace et la capacité nœud sont **deux contraintes indépendantes** (l'une protège les environnements entre eux, l'autre reflète la machine physique partagée) — les additionner ou les confondre serait trompeur, d'où deux jauges distinctes plutôt qu'une fusion.

**Implémentation** :

- `K8sManifestApplyService.getClusterCapacity()` (nouveau) : somme l'`allocatable` CPU/mémoire de tous les nœuds, puis soustrait les *requests* de tous les pods actifs de **tous les namespaces** (hors `Succeeded`/`Failed`) → `allocatableCpuCores`, `usedCpuCores`, `availableCpuCores` (+ équivalents mémoire).
- **Emplacement primaire (préventif) — modale Déployer** : `ApplicationManagementService.enrichWithClusterCapacity()` appelle `getClusterCapacity()` dans `previewDeploy()` et ajoute un avertissement explicite si la sélection dépasse ce qui est réellement libre sur le nœud. Nouvelle jauge « Capacité réelle du nœud (déjà utilisée par tous les namespaces) » sous la jauge de quota existante, dans `project-deploy-modal.component.html`.
- **Emplacement secondaire (diagnostic) — Runtime & Environments** : même donnée exposée via `getNamespaceMonitoring()` → `clusterCapacity`, affichée comme une puce « Capacité nœud — CPU x % · MEM y % » à côté de la puce « Quota namespace » existante, pour diagnostiquer après coup un pod resté `Pending`.
- Aucune nouvelle table/colonne — donnée calculée à la volée à chaque appel (cohérent avec le choix déjà fait pour le quota namespace).

---

## 8. Addendum — Scénarios de test capacité & garde-fou manquant (18 août 2026)

**Vérification en direct du chantier #7** (captures d'écran fournies par l'utilisateur, tests réels sur le cluster) — trois constats :

1. **Rolling update confirmé en pratique** : modifier les ressources d'un service `back` déjà déployé crée un nouveau ReplicaSet qui tente `limits.cpu=4` EN PLUS des `limits.cpu=3` déjà utilisés par l'ancien → `FailedCreate` (`exceeded quota`). L'ancien ReplicaSet continue de tourner tel quel (d'où « 3/3 Ready » malgré l'échec de la mise à jour) — confirme l'hypothèse de doublement temporaire de conso évoquée §5, jusque-là non prouvée. **Copie du message clarifiée le 18 août 2026** : quand `previewDeploy()` détecte que l'application a déjà un déploiement `RUNNING` (donc que ce clic sur « Déployer » est une mise à jour, pas une première création), l'avertissement de capacité nœud insuffisante (`ApplicationManagementService.enrichWithClusterCapacity()`) précise désormais explicitement que l'ancien et le nouveau pod vont coexister brièvement (rolling update) — pour éviter de laisser croire qu'« insuffisant » veut dire « restera bloqué durablement ».
2. **Garde-fou manquant sur le chemin d'édition** : la jauge + confirmation obligatoire de capacité nœud (§7) n'existe QUE dans la modale Déployer (`project-deploy-modal`). Modifier un service **déjà déployé** passe par `AppDeploymentService.syncServiceRuntime()` (le même mécanisme que la traçabilité sync-runtime, §5) — ce chemin ne vérifiait que le quota namespace côté admission K8s (réactif, après coup), jamais la capacité nœud, et sans aucun avertissement proactif. **Corrigé le 18 août 2026** : nouvelle méthode `ApplicationManagementService.previewServiceResourceChange()` (endpoint `POST /{id}/services/{sid}/resource-preview`), appelée par `saveService()` juste avant d'enregistrer une édition d'un service **déjà déployé** (namespace RUNNING connu). Elle lit l'état RÉEL du cluster — `K8sManifestApplyService.fetchResourceQuotaStatus()` (ResourceQuota K8s live) et `getClusterCapacity()` (capacité nœud) — et projette `usage actuel du namespace + nouvelle valeur du service` (pas un delta ancien→nouveau : pendant une mise à jour, ancien et nouveau pod coexistent brièvement, cf. constat 1 ci-dessus, donc la vraie contrainte est bien `used + new`). Si le quota namespace OU la capacité nœud seraient dépassés, une confirmation bloquante (`confirm()`, même seuil de gravité que la modale Déployer) est exigée avant d'enregistrer ; sinon l'édition se poursuit sans friction. Best-effort : n'empêche jamais l'édition si le cluster/l'aperçu est indisponible. N'ajoute rien pour la création d'un nouveau service (jamais hot-appliquée directement — passe par la modale Déployer, déjà protégée).
3. **Lisibilité de l'incident quota** : quand des pods sont rejetés par le quota, ils n'existent jamais comme objets Kubernetes — l'onglet Pods de Runtime ne peut donc afficher QUE les pods qui existent (tous `SUCCESS`), ce qui masque le problème. Il n'est visible que dans Workloads (ready < désiré, badge « Degraded ») et dans les Événements/Alertes (`FailedCreate`). Comportement correct (pas un bug), mais contre-intuitif. **Corrigé le 18 août 2026** : bandeau d'avertissement ajouté en tête de la section « Pods — détail ressources » (`monitoring-dashboard.component`) quand `ready < desired` sur au moins un workload — « N pod(s) manquant(s) sur « nom » — n'existe pas encore comme objet Kubernetes (quota namespace ou capacité nœud probablement atteinte)… », avec renvoi vers Workloads/Alertes pour la cause exacte (`missingPodsCount`/`degradedWorkloadNames`, dérivés côté client depuis `workloads`, aucune donnée backend supplémentaire).

**Limite connue, non corrigée (acceptée en l'état)** : le contrôle de capacité nœud dans la modale Déployer est une vérification instantanée (« au clic »), pas continue — deux déploiements lancés à quelques secondes d'intervalle (deux onglets, deux utilisateurs) peuvent chacun voir de la marge au moment de leur propre vérification et se marcher dessus, sans verrou global. Comportement acceptable pour un outil mono-utilisateur/petite équipe, documenté ici pour ne pas être redécouvert par surprise.

Document complémentaire avec scénarios de test pas-à-pas (depuis l'interface, sans commande) : voir l'artefact « Scénarios de capacité — EnviroTest ».
