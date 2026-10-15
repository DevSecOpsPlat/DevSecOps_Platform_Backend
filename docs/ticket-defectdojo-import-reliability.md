# Ticket — Fiabilité de l'import DefectDojo (`deploy:defectdojo-import`)

> Ouvert suite au diagnostic du score de posture du 29/08/2026 (voir `audit-quality-gate.md`).
> Statut : **diagnostiqué, non corrigé** — proposition à valider avant implémentation, même
> processus que pour la recalibration de `SecurityScoringService`.

## 1. Symptôme observé

Dans l'échantillon des 30 derniers `quality_gate_snapshots`, 5 des 6 pipelines à score "propre"
(85 ou 100) affichaient `metrics.bySeverity` à `{critical:0, high:0, medium:0, low:0}` alors que
`toolMetrics[grype]` montrait, pour le **même pipeline**, des dizaines de findings critiques/high
(ex. pipeline 2785595612 : Grype à 13 critical / 114 high, `bySeverity` à zéro). Un score "propre"
qui masque en réalité une absence de données est plus dangereux qu'un score bas — c'est ce point
précis qui justifie ce ticket séparé.

## 2. Diagnostic — le job échoue-t-il, ou est-il en retard ?

**Ni l'un ni l'autre.** Vérifié en direct via l'API GitLab (`GET /projects/79441224/pipelines/{id}/jobs`)
sur les 30 pipelines de l'échantillon :

| Pipeline | Job `deploy:defectdojo-import` |
|---|---|
| 2800542049, 2800472710, 2800207356 (3 plus récents) | **présent, `success`** |
| Les 25 autres (plus anciens) | **absent** — n'apparaît même pas dans la liste des jobs du pipeline |

Le job est défini avec `rules: - if: '$ACTION == "deploy" && $DD_IMPORT_ENABLED == "true"'`
([EnviroTest/.gitlab-ci.yml:1931](../../EnviroTest/.gitlab-ci.yml#L1931)). La variable
`DD_IMPORT_ENABLED=true` n'était envoyée par la plateforme aux déclenchements de pipeline que
depuis un correctif fait **plus tôt dans cette même session** (`AppDeploymentService` — voir
`audit-quality-gate.md` §6, journal des correctifs). Tous les pipelines antérieurs à ce correctif
ne satisfaisaient donc jamais la condition `rules` : le job n'a **jamais été déclenché**, ce n'est
ni un échec ni un ralentissement — la frontière est nette et coïncide exactement avec l'identifiant
de pipeline où le correctif a pris effet.

**Conclusion du diagnostic** : l'anomalie précise repérée dans l'échantillon est entièrement
expliquée, et déjà résolue de fait pour les nouveaux pipelines par un correctif antérieur —
aucune régression active sur les 3 pipelines post-correctif observés (tous `success`). Il ne
s'agit donc pas d'un bug actif à corriger dans l'immédiat.

## 3. Ce qui reste un vrai risque (au-delà du symptôme déjà expliqué)

Le job garde `allow_failure: true` ([EnviroTest/.gitlab-ci.yml:1939](../../EnviroTest/.gitlab-ci.yml#L1939)),
et son échec (import DefectDojo indisponible, timeout réseau, fichier de rapport vide, etc.) n'est
signalé nulle part côté plateforme : `buildBySeverity()`/`resolveContainerSeverity()`/
`resolveDastSeverity()` lisent `dd.getBySeverity()` etc. et, si le résultat est vide, le traitent
**silencieusement comme "aucun finding"** plutôt que comme "donnée indisponible" — exactement le
mécanisme qui a produit le symptôme du §1, cette fois-ci pour une raison potentiellement différente
(échec réel futur du job, pas seulement son absence historique). Avec seulement 3 exécutions
post-correctif observées (toutes réussies), l'échantillon est trop restreint pour garantir que ce
chemin ne se reproduira jamais pour une vraie raison de fiabilité (DefectDojo temporairement
indisponible, upload volumineux qui time out, etc.) : le risque structurel, lui, reste réel.

## 4. Piste de correctif (proposée, non implémentée)

Trois options possibles, à combiner ou choisir — **en attente de validation avant tout code** :

1. **État `INDETERMINATE` tant que l'import n'est pas confirmé**, plutôt qu'un `bySeverity` vide
   traité comme "aucun finding". Nécessite un signal explicite de succès d'import (le job CI logue
   déjà `HTTP $HTTP_CODE OK/FAILED` par outil — il faudrait le remonter à la plateforme, ex. via le
   webhook déjà utilisé par `deploy:grype-scan` pour le scan container).
2. **Webhook de statut dédié**, symétrique à celui déjà en place pour `deploy:grype-scan`
   ([EnviroTest/.gitlab-ci.yml:1604](../../EnviroTest/.gitlab-ci.yml#L1604)) : `deploy:defectdojo-import`
   poste son propre statut (succès/échec par outil importé) vers la plateforme, qui peut alors
   distinguer "import confirmé, 0 finding réel" de "import jamais confirmé".
3. **Retry** sur le `curl` d'import lui-même (déjà `allow_failure: true`, donc un échec transitoire
   n'interrompt jamais le pipeline — un retry immédiat en cas d'échec HTTP réduirait le risque sans
   changer ce comportement).

Recommandation : (1)+(2) ensemble (le webhook est le signal, l'état INDETERMINATE est la
conséquence côté score) -- (3) seul ne résout pas le cas où DefectDojo est indisponible plus
longtemps qu'un retry ne peut couvrir. Mais **la donnée manque encore pour trancher précisément**
(seulement 3 exécutions post-correctif observées, 0 échec parmi elles) : contrairement aux pistes
A/B de `SecurityScoringService`, ce correctif n'a pas encore de cas d'échec réel observé à
reproduire — à surveiller sur les prochains pipelines avant d'investir dans l'implémentation.

## 5. Fichiers concernés (si implémenté)

| Fichier | Rôle |
|---|---|
| `EnviroTest/.gitlab-ci.yml` (job `deploy:defectdojo-import`, ligne ~1927) | Ajouter le webhook de statut |
| `QualityGateService.buildBySeverity()` / `resolveDastSeverity()` / `resolveContainerSeverity()` | Distinguer "import confirmé vide" de "import jamais confirmé" |
| `SecurityScoringService.evaluateHardGates()` | Ajouter un état INDETERMINATE si l'import n'est pas confirmé |
