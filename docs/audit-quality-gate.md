# EnviroTest — Quality Gate : mécanique complète + journal des correctifs

> Référence interne, dans le même esprit que `audit-deploiement.md` mais pour le module **Quality
> Gate** (verdict de déploiement, score de posture, hard gates, DAST/post-déploiement). Rédigé à
> partir d'une lecture directe du code + vérification live (base Postgres, API GitLab, API
> DefectDojo, API SonarQube, cluster K8s) pendant la session du 28 août 2026. Les formules et seuils
> ci-dessous sont recopiés tels quels depuis le code source à la date de rédaction — en cas de
> divergence future, le code fait foi, pas ce document.

## Sommaire

1. [Vue d'ensemble du processus](#1-vue-densemble-du-processus)
2. [Les hard gates (bloquants, tolérance zéro)](#2-les-hard-gates-bloquants-tolérance-zéro)
3. [Le score de posture — l'équation complète](#3-le-score-de-posture--léquation-complète)
4. [Résolution du verdict final](#4-résolution-du-verdict-final)
5. [Le module Post-déploiement (DAST, smoke test, scan container)](#5-le-module-post-déploiement-dast-smoke-test-scan-container)
6. [Journal des correctifs — session du 28 août 2026](#6-journal-des-correctifs--session-du-28-août-2026)
7. [Fichiers clés](#7-fichiers-clés)

---

## 1. Vue d'ensemble du processus

Le Quality Gate d'EnviroTest répond à une seule question — *"peut-on déployer ce code ?"* — en
deux temps strictement séquentiels, jamais mélangés :

```
Résultats scanners (SonarQube, DefectDojo, GitLab CI)
   │
   ▼
① HARD GATES — déterministes, tolérance zéro
   secrets exposés · vulnérabilités critiques · issues Blocker Sonar
   Quality Gate Sonar en ERROR · DAST (ZAP) au-delà du seuil
   │
   ├── Une seule violation ⇒ NON_RECOMMANDE, immédiatement, sans même
   │   regarder le score.
   ├── Une source indisponible (Sonar injoignable, DefectDojo down,
   │   scan DAST pas terminé…) ⇒ INDETERMINE — pas "recommandé par
   │   défaut", l'absence de donnée n'est jamais traitée comme un succès.
   │
   ▼ (si aucune violation ET aucune source indéterminée)
② SCORE DE POSTURE — informatif, 100 points de départ, pénalités
   par densité de findings (ou en absolu si le code n'est pas assez
   volumineux pour que la densité ait un sens) + qualité SonarQube.
   │
   ▼
Verdict final = déterministe (①) sinon dérivé du score (②)
```

**Point important, corrigé cette session (§6.3)** : le score (②) est désormais **toujours calculé**,
même quand ① bloque le déploiement — avant, un hard gate violé empêchait le calcul du score
lui-même, qui restait invisible à côté d'un verdict "Non recommandé", privant l'utilisateur de tout
signal sur la gravité relative du problème. La logique de verdict (①) n'a, elle, pas changé d'un
bit : un score de 95/100 ne rattrape jamais un secret exposé.

---

## 2. Les hard gates (bloquants, tolérance zéro)

Évalués par `SecurityScoringService.evaluateHardGates()`. Chaque gate a trois états possibles —
**OK** (silencieux), **VIOLATED** (bloque le déploiement) ou **INDETERMINATE** (source de donnée
indisponible — traité comme "je ne sais pas", jamais comme "c'est bon").

| Gate (id) | Condition de violation | Condition d'indétermination | Source |
|---|---|---|---|
| `secrets` | ≥ 1 secret détecté (Gitleaks) | Job secrets non exécuté | GitLab CI (summary) |
| `dd_critical` | ≥ 1 vulnérabilité critique — DefectDojo **+ SonarQube** critiques cumulés si Sonar dispo | DefectDojo injoignable | DefectDojo + SonarQube |
| `sonar_blocker` | ≥ 1 issue *Blocker* SonarQube | SonarQube injoignable | SonarQube |
| `sonar_qg` | Quality Gate SonarQube en statut `ERROR` | SonarQube injoignable | SonarQube |
| `dast` | > 5 findings *High* ZAP (`QualityGateThresholds.DAST_HIGH`) | Scan DAST non exécuté/incomplet | GitLab CI + DefectDojo |

Le gate `dast` a une particularité, **corrigée cette session** (voir §6.1‑§6.2) : il ne s'applique
QUE si `execution.getExecutionKind() == DEPLOY` (`dastApplicable`) — ZAP ne tourne jamais sur un
pipeline scan-only, donc le gate reste silencieusement absent dans ce cas, au lieu d'être compté à
tort comme "non exécuté" (indéterminé) sur une exécution où il n'a jamais eu vocation à tourner.

---

## 3. Le score de posture — l'équation complète

Calculé par `SecurityScoringService.computePostureScore()`. Toujours sur 100 points, décroissant.

### 3.1 Choix densité vs absolu

```
useDensity = (ncloc ≥ 100)
```
Si le projet a assez de lignes de code pour que "findings pour 1000 lignes" ait un sens statistique,
la pénalité est proportionnelle à la **densité** ; sinon, repli sur un compte **absolu** (évite de
punir disproportionnellement un micro-service de 50 lignes).

### 3.2 Pénalité par sévérité (SCA/SAST/Secrets, via DefectDojo)

Pour chaque sévérité `s ∈ {critical, high, medium, low}` avec un compte `n_s > 0` :

**Mode densité** (`ncloc ≥ 100`) :
```
densité_s = weightedCount_s × 1000 / ncloc
impact_s  = round( min(30, densité_s × facteur_densité_s) )
```

**Mode absolu** (repli, `ncloc < 100`) :
```
impact_s = round( weightedCount_s × facteur_absolu_s )
```

| Sévérité | facteur densité | facteur absolu (repli) |
|---|---|---|
| Critical | 12.0 | 8 |
| High | 4.0 | 3 |
| Medium | 1.5 | 1 |
| Low | 0.4 | 0.25 |

Chaque pénalité de densité est plafonnée individuellement à **30 points** (`min(30, …)`) — un seul
bucket de sévérité ne peut jamais, à lui seul, épuiser tout le score.

> **Mise à jour du 29/08/2026** : ce plafond individuel n'empêchait pas 3 buckets de saturer
> *simultanément* (`critical`+`high`+`medium` à −30 chacun = −90 à eux seuls) — voir §3.6bis pour le
> plafond global ajouté sur la somme des 4 buckets, et §6.14 pour le diagnostic complet.

### 3.3 Pondération CVSS (`weightedCount`)

`weightedCount_s` n'est pas toujours égal au compte brut `n_s` : si un CVSS moyen est connu pour ce
bucket de sévérité (issu d'un échantillon de findings DefectDojo déjà chargé, aucun appel
supplémentaire), le compte est modulé autour du **point médian CVSS v3.1 standard** de cette
sévérité :

```
midpoint_s ∈ {critical: 9.5, high: 8.0, medium: 5.5, low: 2.0}
weight     = clamp( CVSS_moyen / midpoint_s , 0.5 , 1.5 )
weightedCount_s = (nombre_avec_CVSS_connu × weight) + nombre_sans_CVSS_connu
```
Sans donnée CVSS pour ce bucket : repli sûr, `weightedCount_s = n_s` (comportement identique à
avant l'introduction de cette pondération — jamais de régression silencieuse).

### 3.4 Dimension DAST (ZAP) — à part

```
impact_dast_high   = pénalité(dast_high,   facteur_densité=4.0,  facteur_absolu=3)
impact_dast_medium = pénalité(dast_medium, facteur_densité=1.5,  facteur_absolu=1)
```
Ligne de détail **séparée**, jamais fondue dans les buckets crit/high/med/low ci-dessus (le DAST a
sa propre nature — vulnérabilités observées à l'exécution, pas dans le code source) — et seulement
si `dastApplicable` (pipeline de déploiement).

### 3.4bis Dimension conteneur (Grype) — à part, paliers absolus (29/08/2026)

Comme le DAST : ligne de détail **séparée**, jamais fondue dans crit/high/med/low — la soustraction
se fait dans `QualityGateService.buildBySeverity()`, symétriquement à la soustraction DAST déjà en
place (`dd.getContainerBySeverity()`, nouveau champ sur `DefectDojoDashboard2Response`, résolu par
`DefectDojoService.parallelCountBySeverityForTaggedTestsByScanType(..., {"grype","anchore","container"})`).

Contrairement au DAST, **pas de densité par ncloc** : le nombre de vulnérabilités d'une image de
base (paquets OS/runtime) n'a structurellement aucun lien avec la taille du code source applicatif
— diagnostic du 29/08/2026, voir §6.14. Paliers absolus à la place :

```
impact_container_s = palier(count_s, seuils_s, impacts_s)   -- indépendant de ncloc
```

| Sévérité | Seuils (bornes hautes) | Impacts | Plafond |
|---|---|---|---|
| Critical | 3 · 8 · 15 | 8 · 16 · 25 · 30 | 30 |
| High | 15 · 50 · 120 | 8 · 16 · 24 · 30 | 30 |
| Medium | 10 · 40 · 90 | 6 · 14 · 22 · 30 | 30 |
| Low | 8 · 20 | 6 · 14 · 30 | 30 |

Seuils calibrés sur les comptages réels observés sur l'échantillon de 30 pipelines du diagnostic
(critical 7–13, high 44–144, medium/low majoritairement à 0 avec quelques cas à 90+/25) —
**provisoires**, à recalibrer avec davantage de données (constantes `CONTAINER_*` dans
`SecurityScoringService`).

### 3.5 Pénalités qualité SonarQube (si Sonar disponible)

| Composant | Condition | Impact |
|---|---|---|
| Rating Security | D | **−10** |
| Rating Security | E | **−15** |
| Rating Reliability | D | −5 |
| Rating Reliability | E | −8 |
| Couverture de tests | < 50 % | −5 |
| Security hotspots | > 0 | `−min(10, round(hotspots × 0.5))` |

### 3.6bis Plafonds globaux (29/08/2026)

Deux plafonds indépendants, appliqués **après** que chaque bucket individuel a déjà été calculé et
plafonné à 30 (rognage de la somme finale, pas d'arrêt anticipé de l'accumulation — choix délibéré :
plus simple, plus prévisible, n'exige pas de choisir un ordre d'évaluation des buckets) :

```
severitySum       = impact_critical + impact_high + impact_medium + impact_low
severityApplied   = min(severitySum, 70)        -- SEVERITY_GLOBAL_CAP

containerSum      = impact_container_critical + impact_container_high
                   + impact_container_medium  + impact_container_low
containerApplied  = min(containerSum, 70)       -- CONTAINER_GLOBAL_CAP
```

Chaque ligne de détail individuelle (`dd_critical`, `container_high`, …) garde sa vraie valeur dans
`breakdown[]`, même quand le plafond réduit ce qui est réellement appliqué au score — transparence
délibérée. `SecurityScoreDto.appliedCaps` liste les plafonds qui se sont déclenchés
(`severity_global_cap` / `container_global_cap`) ; `rawScoreBeforeCaps` porte désormais la vraie
somme avant plafonds (peut être négative) — avant ce correctif, ce champ ne faisait que refléter le
score déjà plafonné, silencieusement inexploitable.

**Provisoire** : plafond de 70 calibré sur un échantillon de 30 pipelines (diagnostic du
29/08/2026, §6.14) — à revoir avec davantage de données. Sans dépassement (cas normal, la grande
majorité des projets), les deux plafonds sont un no-op strict : score identique au comportement
d'avant ce changement (garde de non-régression testée, voir `SecurityScoringServiceTest`).

### 3.6 Score final, grade, verdict dérivé

```
score = clamp( 100 − severityApplied − containerApplied
                   − impact_dast_high − impact_dast_medium
                   − Σ(pénalités SonarQube) , 0 , 100 )

grade :  A ≥ 90  ·  B ≥ 75  ·  C ≥ 60  ·  D ≥ 40  ·  E < 40

verdict_dérivé = WITH_WARNINGS  si (score < 75) OU (un stage en statut WARN)
                = RECOMMENDED   sinon
```

---

## 4. Résolution du verdict final

`SecurityScoringService.resolveDeterministicVerdict(hardGates, postureScore)` — la seule fonction
qui décide du verdict affiché, dans cet ordre strict :

```
1. Une violation de hard gate     → NON_RECOMMANDE   (le score n'est jamais consulté)
2. Une source indéterminée        → INDETERMINE      (jamais "recommandé par défaut")
3. Sinon → le verdict dérivé du score (§3.6)          RECOMMENDED | WITH_WARNINGS
4. Repli ultime (ne devrait jamais arriver)            WITH_WARNINGS
```

C'est cette hiérarchie stricte qui a permis, cette session, de rendre le score **toujours visible**
(§6.3) sans changer la moindre décision de déploiement : le score n'entre en jeu qu'à l'étape 3,
jamais avant.

---

## 5. Le module Post-déploiement (DAST, smoke test)

Signaux qui n'existent **qu'après** un déploiement réel, donc volontairement séparés du Quality
Gate pré-déploiement (le DAST ne peut structurellement jamais être un vrai gate *avant*
déploiement : son résultat n'existe qu'une fois l'application déployée).

- **DAST (ZAP)** : scanne l'URL publique de **chaque service** séparément (chaque service a sa
  propre URL/pipeline) — pas un scan "de l'app" au singulier.
- **Smoke test** : ping HTTP de l'URL publique de chaque service dès que ses pods passent Ready
  (`AppDeploymentService.runSmokeTest()`), pour vérifier que l'appli répond vraiment, pas juste que
  le pod a démarré.

Le **scan container (Grype)** a été retiré de cette page (chantier "Post-déploiement v2", §6.15) :
Grype tourne aussi bien en pipeline scan-only qu'en déploiement — ce n'est donc pas un signal
post-déploiement par nature, contrairement à ZAP (attaque une URL live) et au smoke test (ping des
pods vivants). Ses résultats restent consultables via la Quality Gate "par service" (exécutions
SCAN), pas dupliqués ici.

Page dédiée (`post-deploy.component`), par service (sélecteur branche + environnement) :
- **Déclenchement à la demande** : "Relancer" pour le smoke test uniquement (sans restriction,
  coût quasi nul — sonde en HTTP directement, aucun pipeline déclenché). Une relance DAST à la
  demande (`ACTION=dast-only`) a existé brièvement puis a été retirée (§6.17) : sans intérêt réel,
  un résultat ZAP ne change que si le code change, ce qui exige de toute façon un redéploiement
  complet.
- **Matrice à 6 états** par outil (jamais scanné / en cours / 0 finding / N findings / échec /
  obsolète), badges à forme distincte (cercle / carré / triangle — pas la couleur seule) — voir
  §6.15 pour le détail.
- Liste détaillée des findings ZAP filtrable par sévérité, bouton "Détails & IA" par ligne
  (réutilise le flux existant de `security-dashboard.component`, pas de composant recréé).

**Limite connue, non corrigée** : le scan DAST ne couvre qu'**un seul service** par déploiement --
`deploy:zap-dast` scanne une seule variable `$APP_URL`, résolue côté backend par
`AppDeploymentService.resolvePublicUrl()`, qui retourne délibérément l'URL du **frontend** (ou le
premier service exposé hors `/api`), jamais celle du backend (commentaire du code : éviter que la
bannière UI affiche l'URL de l'API). Pour un déploiement front+back, ZAP scanne donc toujours le
frontend, jamais le `/api` du back -- ce n'est pas un bug de ce chantier, la limite préexistait.
Corrigerait ceci : faire boucler `deploy:zap-dast` sur `service-images.json`/les URLs de chaque
service exposé (même principe que le scan Grype multi-images d'avant son retrait, §6.15), avec
fusion des rapports -- pas fait, en attente de decision.

---

## 6. Journal des correctifs — session du 28 août 2026

Chaque item : symptôme observé (souvent en testant la plateforme réelle), cause racine trouvée dans
le code, correctif appliqué.

### 6.1 Bannière "Recommandation peu fiable" — faux "non exécuté"

**Symptôme** : Checkov/Hadolint/OWASP ZAP marqués "non exécuté" alors que le pipeline passait
entièrement (ZAP en particulier : marqué non exécuté même sur un pipeline *scan*, où il ne tourne
jamais par construction).
**Cause** : `collectUnreliableScanJobs()` ne distinguait pas scan/deploy pour ZAP ; `indexJobs()`
collapsait plusieurs jobs GitLab partageant un même *stage* (`sast` = semgrep-sast **+**
hadolint-dockerfile) en une seule entrée, perdant le second job.
**Correctif** : ajout du filtre `dastApplicable` pour ZAP ; `findJob()` gagne un 3ᵉ passage de
repli par préfixe sûr (`jn.equals(alias) || jn.startsWith(alias + "-")`, jamais de `contains()` brut
— évite la collision `setup` / `sonarqube-setup`).

### 6.2 Hard gate DAST — no-op structurel en multi-services

**Cause** : `ScanBatchAggregationService.buildHardGateInput()` ne lisait jamais les champs
`dastApplicable/dastEvaluable/dastCritical/High/Medium` du `gate` figé.
**Correctif** : `freezeDefectDojoRollupFields()` fige aussi ces champs DAST à plat ; le builder les
relit.

### 6.3 Score de posture toujours calculé

Voir §1 et §4. `buildResult()` calcule `securityScore` inconditionnellement (avant : seulement si
aucun hard gate violé) — la logique de verdict (§4) reste identique, seule la **visibilité** du
score change.

### 6.4 SonarQube — trois couches de péremption superposées

1. **Clés de métriques invalides** : `GitLabService.SONAR_MEASURE_KEYS` contenait 12 clés
   invalides sur SonarQube 26.x (`software_quality_security_high_issues` et consorts, vérifiées
   inexistantes via appel direct à l'API réelle) — un seul appel combiné, une seule clé invalide
   ⇒ HTTP 400 ⇒ **toutes** les métriques Sonar silencieusement perdues. Retirées.
2. **Affichage "0" au lieu de "—"** : `getRatingLabel()` (frontend) traitait `0` (sentinelle
   "inconnu" côté backend) comme une note réelle. `SoftwareQualityDimensionDto.ratingValue`
   passé d'`int` à `Integer` (nullable) pour ne plus confondre "vraiment 0" et "inconnu" au niveau
   JSON.
3. **Priorité à l'instantané figé même avec `refresh=true`** : `fetchSonarForQualityGate()`
   consultait toujours l'instantané figé à l'ingestion CI *avant* un éventuel appel live, y compris
   quand l'utilisateur cliquait "Actualiser". Un pipeline ingéré avant le correctif (1) restait donc
   coincé sur ses anciennes données invalides indéfiniment. Corrigé : `refresh=true` tente l'appel
   live **en premier**, repli sur l'instantané figé seulement si Sonar est injoignable.

### 6.5 Sélecteur de lot + cohérence "Scan en cours" (page Quality Gate app)

**Symptôme** : lancer un nouveau scan pendant qu'un ancien lot existe affichait "Non recommandé"
**et** "Scan en cours" simultanément (la grille "Par service" était la seule section sans le garde-
fou `!activeBatchRunning` que le reste de la page avait déjà).
**Correctif** : nouvelle surcharge `securityPosture(appId, batchId)`, sélecteur de lot dans l'UI
(défaut = le plus récent), nouveau getter `isSelectedBatchRunning` dérivé du lot **affiché** (pas
d'un état de polling séparé) — un seul point de vérité, un seul message "Scan en cours" pour toute
la page.

### 6.6 Page Quality Gate app lente (N+1 GitHub synchrone)

**Cause** : `refreshHeadCacheIfStale()` faisait un appel GitHub live **par service**, en boucle
séquentielle, dans le chemin d'une requête HTTP (jusqu'à 10 s × N services).
**Correctif** : retiré du chemin synchrone, déplacé dans un nouveau `HeadCacheRefreshScheduler`
(arrière-plan, toutes les 3 min) — l'indicateur "obsolète" reste correct à quelques minutes près,
acceptable pour un badge informatif, pas un hard gate.

### 6.7 ZAP jamais importé dans DefectDojo pour les pipelines de déploiement

**Cause** : `deploy:defectdojo-import` (`.gitlab-ci.yml`) a pour règle
`$ACTION == "deploy" && $DD_IMPORT_ENABLED == "true"` — variable à `"false"` par défaut dans tout
le fichier. Ce job ne s'était **jamais** exécuté, sur aucun déploiement, depuis sa création.
**Correctif** : `DD_IMPORT_ENABLED=true` passé comme variable au **déclenchement** du pipeline côté
backend (`AppDeploymentService`), pas écrit dans le fichier (convention du projet : l'outil ne
modifie pas `.gitlab-ci.yml`).
**Piège trouvé en le déployant** : le premier correctif avait atterri sur la branche
`feat/multi-service-deploy`, alors que les déploiements réels tournent sur `master`
(confirmé via l'API GitLab, `ref: master`) — sans effet tant qu'il n'était pas sur la bonne branche.
`master` s'est aussi révélé avoir la clé YAML `deploy:grype-scan:` **dupliquée** (deux définitions du
même job) — YAML ne garde que la dernière, celle réellement exécutée par GitLab ; seule celle-là a
été modifiée.

### 6.8 Carte DAST — chiffres incohérents avec les vrais findings

**Symptôme** : carte "DAST — OWASP ZAP" affichant "12 high" alors que DefectDojo n'avait, pour ce
pipeline, que 0 critical/high, 3 medium, 5 low, 4 info sur les mêmes findings.
**Cause** : l'entrée "zap" de `buildToolMetrics()` lisait directement `summary.dast.high/medium`
(comptage fait par un script `jq` dans `.gitlab-ci.yml`, sur les *groupes* d'alertes du rapport ZAP
brut — pas fiable), au lieu de `resolveDastSeverity()` — fonction sœur qui, elle, préfère
correctement les vrais findings DefectDojo dès qu'ils sont disponibles (déjà utilisée pour le hard
gate, jamais pour l'affichage de la carte outil).
**Correctif** : la carte "zap" est repatchée avec les valeurs de `resolveDastSeverity()` juste après
son calcul, `low` ajouté à cette fonction (absente jusque-là).

### 6.9 Liste de findings détaillés — un outil verbeux en masque un autre

**Symptôme** : onglet "ZAP (0)" alors que 12 findings ZAP existaient réellement, "Grype (349)"
tronqué à 100 affichés.
**Cause** : `DefectDojoService.listFindings()` plafonne `size` à 100
(`Math.min(size, 100)`) côté serveur ; une requête combinée par tag pipeline (ZAP + Grype mélangés,
triés par sévérité) laissait Grype (349 findings) noyer entièrement ZAP (12) hors de la page.
**Correctif** : nouvel endpoint `GET /api/defectdojo/tests` (résout le testId exact de chaque outil
pour un pipeline) ; le frontend interroge ensuite `GET /api/defectdojo/findings?testId=…` **une
fois par outil**, chacun avec sa propre pagination — plus de risque qu'un outil en masque un autre.

### 6.10 Smoke test — certificat TLS invalide

**Cause** : la sonde interne (contournement DNS Windows, IP Traefik directe + header `Host` forcé)
réutilisait le schéma de l'URL **publique** (`https://`), alors que Traefik n'écoute qu'en **HTTP**
en interne (`router.entrypoints: web` — TLS terminé par le tunnel Cloudflare en amont, jamais par
Traefik). Résultat systématique : `certificate_unknown`, SAN ne correspondant jamais à l'IP brute.
**Correctif** : schéma forcé à `http://` pour cette sonde interne spécifiquement.

### 6.11 Smoke test — course avec l'application d'Ingress

**Cause** : le smoke test ne se déclenchait qu'au premier passage à `RUNNING` (`firstReady`) ; si
l'Ingress n'était pas encore appliqué à ce tick précis (Ingress appliqué *après* la readiness des
pods, en soft-fail), `externalUrl` était `null` pour tous les services et le test échouait en
silence, **pour toujours** sur ce déploiement (jamais retenté).
**Correctif** : déclenchement reconditionné sur "aucun résultat encore enregistré" au lieu de
`firstReady` seul — retente à chaque poll suivant tant qu'aucun résultat n'existe.

### 6.12 Namespace bloqué en Terminating — conflit de routing Traefik

**Symptôme réel, reproduit en direct** : `https://aoo-1.envirotest.cloud/api/*` → `503 no available
server`, alors que les pods du déploiement actif étaient `1/1 Running` et sains.
**Cause, confirmée via kubectl** : un ancien namespace (`env-aoo-1-70ec73bc`) bloqué en
`Terminating` depuis 29h (un pod refusant de mourir) — son `Ingress` et ses `EndpointSlices`
(pointant vers un pod déjà mort) restaient présents et en conflit avec le namespace actif pour le
**même hostname personnalisé**. Risque général : toute app avec hostname personnalisé peut casser
silencieusement si un teardown précédent reste bloqué — pas spécifique à cette app.
**Correctif à deux niveaux** :
- Réactif : `K8sManifestApplyService.deleteNamespace()` force la suppression des pods restants si
  le namespace ne finit pas de se supprimer en 120 s.
- Proactif : nouveau `StuckNamespaceCleanupScheduler` — balaie **tous** les namespaces de la
  plateforme toutes les 5 min, nettoie tout ce qui reste bloqué en Terminating depuis > 5 min,
  quelle que soit la cause du blocage (pas seulement les teardowns normaux).

### 6.13 Déploiement multi-services — traçabilité manquante pour les services "non représentants"

**Symptôme** : en déployant toute l'app (front + back ensemble), seul `front` obtenait un nouvel
environnement de déploiement suivi — `back` restait indéfiniment sur son dernier **Scan**, même
après plusieurs redéploiements complets de l'app.
**Cause** : `AppDeploymentService.deploy()` ne créait un `PipelineExecution` DEPLOY que pour
`target.getServices().stream().findFirst()` (un seul "service représentant" arbitraire) ; une garde
(`findByGitlabPipelineId`, sans filtrer par service) faisait croire qu'un service avait déjà son
exécution dès que le représentant avait créé la sienne, empêchant silencieusement la création pour
les autres. Le flux Scan, lui, bouclait déjà correctement sur tous les services
(`ScanBatchWriteService.createPendingBatch`).
**Correctif** : `deploy()` boucle sur tous les services de l'app et crée une `PipelineExecution`
pour chacun (tous partagent le même `gitlabPipelineId`/environnement — un seul pipeline GitLab pour
toute l'app) ; la garde est scopée service **+** pipeline
(`findByGitlabPipelineIdAndApplicationId`), plus seulement pipeline.

### 6.14 Score de posture à 0 — diagnostic + recalibration (29/08/2026)

**Symptôme** : `computePostureScore()` retombait à 0/100 sur la majorité des apps testées.
**Diagnostic** (30 derniers `quality_gate_snapshots`, requête directe + script Node.js sur les
payloads dumpés — voir méthode au §1 de ce document) :
- Sur les 11 snapshots avec un score calculé, 5 étaient exactement à 0, 5 exactement à 100,
  1 à 85 — distribution bimodale, quasi rien entre les deux.
- Dans les 5 cas à 0, **`dd_critical`+`dd_high`+`dd_medium` saturaient systématiquement (5/5) leur
  plafond individuel de −30 simultanément** (−90 à eux seuls) — aucun plafond n'existait sur la
  somme des 4 buckets. Somme réelle avant plafond (recalculée à la main, `rawScoreBeforeCaps` étant
  alors non fiable — il ne faisait que refléter le score déjà plafonné) : de −10 à −30 sous le
  plancher.
- Hypothèse initiale de l'utilisateur (mismatch ncloc/SCA, Trivy soupçonné) **confirmée mais avec un
  coupable différent** : Trivy FS n'a tourné que sur 5/30 pipelines (findings non-nuls sur 2/30 —
  quasi inerte dans cet environnement). Le vrai moteur du mismatch est **Grype** (scan d'image
  container, findings 44 à 349 par pipeline) — le nombre de vulnérabilités d'une image de base
  (paquets OS/runtime) n'a structurellement aucun lien avec ncloc (source applicative), exactement
  le mismatch numérateur/dénominateur soupçonné, porté par un scanner différent de celui initialement
  suspecté.
- Effet de bord repéré en cours de route : `toolMetrics[grype]` et `metrics.bySeverity` (ce qui
  alimente réellement le score) pouvaient diverger fortement pour le même pipeline — tracé jusqu'à
  `deploy:defectdojo-import` (`allow_failure: true`, aucun signal de confirmation) → voir
  `ticket-defectdojo-import-reliability.md` (diagnostic séparé, correctif non implémenté).

**Correctif** (validé puis implémenté, `SecurityScoringService` + `QualityGateService` +
`DefectDojoService`) :
1. **Plafond global** sur la somme des 4 buckets de sévérité (§3.6bis), rognage après coup,
   provisoire à 70.
2. **Dimension conteneur (Grype) séparée**, paliers absolus indépendants de ncloc (§3.4bis) —
   choisis plutôt qu'une normalisation par nombre de dépendances car aucune source (rapport Grype
   natif, agrégation CI, DTO backend) n'expose ce total ; Syft ne tourne que pour la conformité
   licence, jamais fusionné au scan de vulnérabilités.
3. Même plafond global appliqué à la dimension conteneur, par cohérence avec (1) — sans lui, un
   pipeline à forte densité Grype aurait simplement reproduit le même mécanisme de dépassement dans
   le nouveau bucket.
4. Correctif de cohérence carte outil "grype" (`toolMetrics`), symétrique au correctif "zap" du
   §6.8 — même classe de bug, même solution.

**Non-régression** : `SecurityScoringServiceTest` étendu (4 nouveaux tests) — un projet sans
dépassement de plafond obtient un score strictement identique à avant (testé explicitement) ; les
17 tests CVSS/DAST préexistants continuent de passer sans modification. Suite complète : 37/37,
0 échec.

### 6.15 Post-déploiement v2 (29/08/2026) — Grype retiré, anti-prolifération DefectDojo, relance à la demande

**Diagnostic préalable** (deux hypothèses vérifiées avant tout code) :
- La requête qui alimente les findings ZAP/Grype de `post-deploy.component`
  (`DefectDojoService.listTestsForPipeline` → tag `pipeline-<id>`) était déjà correctement scopée.
  Le vrai problème (mélange d'outils scan-only + entrées datées dupliquées) vient d'ailleurs : le
  filtre "Outil (import)" de `security-dashboard.component`, alimenté par
  `DefectDojoService.buildScanSnapshotsFast(engagementId)` — `GET /api/v2/tests/?engagement=…&limit=10&ordering=-created`,
  **sans aucun filtre par tag**, ni pipeline ni environnement.
- `deploy:defectdojo-import` (.gitlab-ci.yml) postait inconditionnellement vers `/api/v2/import-scan/`
  — jamais de recherche de Test existant, jamais de `reimport-scan` — contrairement à `smart_import()`
  côté scan. Confirmé cause directe de la prolifération.

**Objectif 1 — Grype retiré du flux déploiement.** `deploy:grype-scan` supprimé de `.gitlab-ci.yml`
(`ACTION=deploy`) ; Grype ne tourne plus que côté scan (`grype-image-scan`, `.scan-rules`) — un
scan de conteneur n'est pas un signal post-déploiement par nature (il tourne aussi bien avant tout
déploiement). Carte + onglet Grype retirés de `post-deploy.component`. Vérifié sans régression :
le hard gate `dd_critical` d'un déploiement dont la branche n'a jamais été scannée reste
`INDETERMINATE` (`resolveDdCritical()`, `availableForHardGate=false` si engagement introuvable) ;
la Quality Gate "par service" n'a jamais filtré `toolMetrics`/grype par `executionKind` — aucune
donnée Grype existante ne devient injoignable.

**Objectif 2 — Anti-prolifération DefectDojo.** `deploy:defectdojo-import` réécrit avec le même
principe que `smart_import()` (scan), adapté : `smart_import()` n'était pas réutilisable telle
quelle (fonction shell locale à un autre job, clé de dédoublonnage `tags=scan` sans sens pour un
déploiement) — clé remplacée par `tags=env-<ENVIRONMENT_ID>` (variable déjà posée par
`AppDeploymentService` à chaque déclenchement de déploiement). Un seul Test actif par outil par
environnement, mis à jour (`reimport-scan`, `close_old_findings=true`) au lieu d'être dupliqué à
chaque déploiement.

**Objectif 3 — Déclenchement à la demande.**
- Smoke test : `AppDeploymentService.rerunSmokeTestForService()` contourne délibérément
  `hasSmokeTestResult()` (qui n'existe que pour éviter de re-sonder à chaque poll CI automatique
  pendant les ~5 min d'attente RUNNING) — un déclenchement manuel explicite n'a pas cette
  contrainte. Corrige le bug historique : un seul résultat enregistré, jamais rafraîchi ensuite.
- DAST : une relance à la demande (`triggerDastOnly()`, pipeline léger `ACTION=dast-only`) a été
  implémentée puis **retirée** — voir §6.17.

**Objectif 4 — Bouton "Détails & IA".** Flux localisé avant tout code : bouton déjà existant dans
`security-dashboard.component.html` (`.vuln-detail-btn`, classe partagée dans
`project/shared/security-list.styles.css`), navigue vers `DefectDojoFindingDetailsComponent` où vit
`AiAnalysisService` — pas recréé, juste réutilisé dans `post-deploy.component`. Diagnostic
supplémentaire au passage : deux échelles de couleurs de sévérité différentes coexistaient
(`security-list.styles.css` : low=vert ; `post-deploy.component.css` : low=**bleu**) — la seconde
supprimée, `post-deploy` utilise désormais l'échelle partagée.

**Objectif 5 — Matrice à 6 états**, par outil (ZAP, smoke test) : jamais scanné / en cours / 0
finding / N findings / échec / obsolète. Système à deux axes forme+couleur (cercle creux → cercle
qui tourne → cercle plein ✓ → carré → triangle + bordure pointillée), pour que la forme reste le
signal principal même en simulation daltonienne. "Obsolète" n'est pas un 7ᵉ état exclusif : un
indicateur orthogonal (comparaison `evaluatedAt`/`checkedAt` vs `deployedAt`) qui se superpose à
l'état primaire (résultat affiché en opacité réduite + légende, jamais remplacé par du vide pendant
un rafraîchissement).

**Effet de bord demandé après coup** : le filtre "Outil (import)" de `security-dashboard.component`
exclut désormais ZAP (`refreshScanToolOptions()`) — cette vue liste les findings sur le code source/
les dépendances, le DAST est une nature de finding différente, déjà consultable dans
`post-deploy.component`.

### 6.16 Quality Gate : score/Sonar figés tant qu'on ne clique pas "Actualiser"

**Symptôme observé** : après la recalibration du score (§6.14), certaines apps affichaient encore
0/100 ; le détail SonarQube restait à 0 jusqu'à un clic manuel sur "Actualiser".

**Cause, vérifiée avec les vraies données** : `getForApplication(..., refresh)` — en chargement
normal (`refresh=false`, le cas par défaut à l'ouverture de la page), le résultat vient d'un
**instantané déjà stocké** en base (`quality_gate_snapshots`, `loadSnapshotForEnvironment`/
`tryLoadSnapshotFromDb`) — jamais recalculé à la volée. Seul `refresh=true` (bouton "Actualiser")
déclenche la reconstruction live (DefectDojo + SonarQube), **sans réécriture en base** (le
commentaire du code le dit explicitement). Un mécanisme de fond
(`captureSnapshotAfterStagesSync`, source `STAGES_SYNC`) resynchronise parfois un instantané
existant — mais il réagit aux changements de statut GitLab, pas au fait que la formule de score ait
changé : il ne rattrape donc pas de façon fiable les anciens instantanés figés avant le correctif du
§6.14. Confirmé en direct : sur 3 pipelines aux données sources identiques (§6.14), un seul montre
le score recalculé (10, plafond appliqué) — les deux autres restent bloqués à l'ancien score (0).

**Pas encore corrigé** — ce n'est pas un bug du moteur de score (hors-scope de ce chantier), c'est
un choix d'architecture (snapshot figé par défaut, probablement pour éviter d'interroger DefectDojo/
SonarQube à chaque ouverture de page) dont l'effet de bord (aucune indication que la donnée
affichée est un instantané, pas l'état courant) mérite un correctif séparé — voir la conversation
pour les options proposées (indicateur de fraîcheur, actualisation automatique conditionnelle, etc.),
en attente d'arbitrage.

### 6.17 Retrait de la relance DAST à la demande (30/08/2026)

**Contexte** : implémentée dans le cadre de l'Objectif 3 (§6.15) — pipeline léger `ACTION=dast-only`
(`deploy:zap-dast-only`), cooldown serveur 15 min, pour vérifier la reproductibilité d'un finding
ZAP sans attendre un nouveau cycle de build.

**Retirée à la demande de l'utilisateur** : un résultat ZAP ne change que si le code change, ce qui
exige de toute façon un redéploiement complet — celui-ci relance déjà `deploy:zap-dast` normalement.
Une relance "sans rebuild" n'apporte donc pas de valeur réelle par rapport à un simple redéploiement.

**Retiré, sur les deux branches et couches** :
- `.gitlab-ci.yml` (`master` + `feat/multi-service-deploy`, sur les deux occurrences dupliquées de
  master) : job `deploy:zap-dast-only` supprimé, `deploy:zap-dast` revient à un script inline
  (ancres YAML `&zap_dast_script`/`&zap_dast_artifacts` retirées, plus nécessaires) ;
  `deploy:defectdojo-import` revient à `ACTION == "deploy"` uniquement, sans `ORIGINAL_PIPELINE_ID`.
- Backend : `AppDeploymentService.triggerDastOnly()` et `DAST_RERUN_COOLDOWN` supprimés ;
  `ApplicationManagementService.rerunDastScan()` et l'endpoint
  `POST /{id}/services/{sid}/dast-scan/rerun` supprimés. `requireRunningDeployment()` conservé
  (encore utilisé par le smoke test).
- Frontend : bouton "Relancer le scan DAST", décompte de cooldown et état `dastRerun` retirés de
  `post-deploy.component` — remplacés par une simple mention informative (un scan se relance
  automatiquement à chaque redéploiement).

**Limite déjà connue, non liée à ce retrait** : le scan DAST ne couvre qu'un seul service par
déploiement (le frontend, jamais le `/api` du back) — voir §5, "Limite connue, non corrigée".

### 6.18 Chantier "sécurité des applications déployées" (31/08/2026)

**Contexte** : jusqu'ici, tout ce document traite de la sécurité *du code* des applications
déployées (le score, les hard gates). Question restée sans réponse : une fois déployée, une
application est-elle protégée à l'exécution — et cette protection est-elle visible pour qui la
supervise ? Chantier séparé, journalisé en détail dans
`docs/audit-securite-apps-deployees.md` (et son complément `docs/admin-securite-reference.md` côté
admin) — résumé ici pour rester dans le même journal que le reste du module.

**Constat principal** (le plus important du chantier) : **détection ≠ blocage**.
`EnviroTest/.gitlab-ci.yml` définit `DEPLOY_GATE_ENFORCE: "false"` (L81) — un verdict
`NON_RECOMMANDE` n'échoue donc jamais le pipeline aujourd'hui, et `AppDeploymentService` ne
consulte à aucun moment le verdict du Quality Gate avant de déployer. Une application avec une
vulnérabilité critique détectée peut être déployée sans aucun obstacle technique. Non implémenté
ici (changement de comportement de production, à valider avant tout code) — deux pistes proposées
dans `audit-securite-apps-deployees.md` §3.

**Mécanismes d'isolation runtime déjà en place, mais jamais documentés ni relus après coup** :
`NetworkPolicy` par défaut-deny (`AppK8sManifestService.networkPolicyManifest`), `ResourceQuota` +
`LimitRange`, identifiants systématiquement via `Secret` K8s — tous actifs par défaut en
production (vérifié dans `application.properties` + `docker-compose.yml`).

**Écart trouvé et corrigé** : le quota était déjà relu et affiché (`fetchResourceQuotaStatus`),
mais l'isolation réseau ne l'était pas — un namespace pouvait avoir perdu sa `NetworkPolicy` (ou ne
jamais l'avoir reçue, namespace antérieur à cette protection) sans que personne ne puisse le voir.

**Ajouté** :
- `K8sManifestApplyService.fetchNetworkPolicyStatus(namespace)` — nouvelle méthode, relit la
  `NetworkPolicy` `default-isolation` réellement présente sur le namespace, exposée dans
  `getNamespaceMonitoring()` sous la clé `networkPolicy`.
- Frontend : carte "Isolation réseau" dans `monitoring-dashboard.component.ts/.html` (badge
  Active/Absente + nombre de règles d'entrée), visible à la fois dans la console admin
  (`admin-monitoring.component.html`) et le monitoring applicatif utilisateur — même composant
  partagé, aucun doublon créé.
- `NetworkPolicyInfo` ajouté à `application-management.models.ts`.

**Limites honnêtes, non corrigées ici** (détaillées dans `audit-securite-apps-deployees.md` §2.4) :
aucun `securityContext` (non-root, no-priv-escalation) imposé sur les conteneurs applicatifs
déployés ; aucune limitation de débit/WAF devant le trafic public d'une application déployée (à la
différence d'EnviroTest elle-même, chapitre 6 du rapport) ; `insecure-skip-tls-verify=true` par
défaut sur la connexion backend→API Kubernetes.

---

## 7. Fichiers clés

| Fichier | Rôle |
|---|---|
| `service/qualitygate/SecurityScoringService.java` | Hard gates + équation du score (§2-§4) |
| `service/qualitygate/QualityGateThresholds.java` | Tous les seuils numériques |
| `service/qualitygate/QualityGateService.java` | Orchestration : construit `sonarFlat`, `toolMetrics`, `dastSeverity`, appelle `SecurityScoringService`, résout le verdict par exécution |
| `service/appmgmt/ScanBatchAggregationService.java` | Agrégation hard gate multi-services (lot) |
| `service/appmgmt/ScanBatchStateService.java` | Checklist par lot (réutilise `ManagedAppScanService.extractQualityGates`, statique) |
| `service/appmgmt/ManagedAppScanService.java` | `securityPosture()` (app), sélecteur de lot, checklist app-level |
| `service/appmgmt/AppDeploymentService.java` | Déclenchement déploiement, `linkDeployPipelineExecution`, smoke test, teardown |
| `service/appmgmt/K8sManifestApplyService.java` | Application manifests K8s, suppression namespace (+ nettoyage forcé) |
| `service/appmgmt/StuckNamespaceCleanupScheduler.java` | Balayage proactif namespaces bloqués |
| `service/appmgmt/HeadCacheRefreshScheduler.java` | Rafraîchissement arrière-plan du cache HEAD (obsolescence) |
| `service/GitLabService.java` | Appels SonarQube (`SONAR_MEASURE_KEYS`), déclenchement pipeline GitLab |
| `service/defectdojo/DefectDojoService.java` | Rollup DefectDojo, `listTestsForPipeline`, findings filtrés |
| `EnviroTest/.gitlab-ci.yml` (dépôt utilisateur) | Pipeline CI réel — stages scan/deploy, `DD_IMPORT_ENABLED`, webhook container-scan |
| `docs/ticket-defectdojo-import-reliability.md` | Ticket séparé — fiabilité de l'import DefectDojo (§6.14), diagnostiqué, non implémenté |
| `docs/audit-securite-apps-deployees.md` | Chantier séparé — sécurité runtime des applications déployées (§6.18) : isolation réseau, quotas, identifiants, constat détection≠blocage |
| `docs/admin-securite-reference.md` | Référence séparée — catalogue exact des capacités admin liées à la sécurité (EnviroTest + apps déployées) |
| `docs/audit-securite-plateforme.md` | Référence séparée — auto-protection d'EnviroTest elle-même (JWT, 2FA, détection de menaces, rate limiting, Nginx), chapitre 6 §2 du rapport |
| `project/quality-gate/quality-gate.component.ts` | Page Quality Gate service unique |
| `application-management/application-detail/application-detail.component.ts` | Page Quality Gate + Post-déploiement app entière |
| `project/post-deploy/post-deploy.component.ts` | Page Post-déploiement (DAST, smoke test) — matrice à 6 états, relance à la demande |
| `project/security-dashboard/security-dashboard.component.ts` | Filtre "Outil (import)", findings détaillés, bouton "Détails & IA" (flux réutilisé par post-deploy) |
| `project/shared/security-list.styles.css` | Échelle de sévérité partagée + `.vuln-detail-btn` (réutilisés par post-deploy, §6.15) |
| `project/post-deploy/post-deploy.component.ts` | Page Post-déploiement (DAST, smoke test, scan container) par service |
