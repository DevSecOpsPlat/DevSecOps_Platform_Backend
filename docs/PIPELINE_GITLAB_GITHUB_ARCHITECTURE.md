# Architecture Pipeline : GitHub ↔ GitLab ↔ PostgreSQL

Ce document décrit en détail comment le pipeline est lancé, comment l’ID de pipeline est partagé entre GitLab et PostgreSQL, comment les détails sont affichés (avec ou sans webhook), comment les stages et résultats sont connus et récupérés, et comment les données sont envoyées/reçues via l’API GitLab.

---

## 1. Comment le pipeline est « lancé » (côté GitHub vs GitLab)

### 1.1 Rôle de GitHub et de GitLab

- **GitHub** : contient le **code source** du projet à déployer. L’utilisateur fournit l’URL du repo GitHub (ex. `https://github.com/user/repo`) et éventuellement un token GitHub pour le clonage.
- **GitLab** : exécute **le pipeline CI/CD**. Le pipeline tourne toujours sur un **projet GitLab** (ex. `amanibennaceur-group/EnviroTest`), dont le fichier `.gitlab-ci.yml` définit les stages (clone, build, scan, etc.).

En résumé : **on ne lance pas le pipeline dans GitHub**. On lance le pipeline **dans GitLab** ; ce pipeline clone ensuite le dépôt GitHub (grâce aux variables `GIT_REPO_URL` et `GITHUB_TOKEN`).

### 1.2 Fichiers impliqués pour le lancement

| Fichier | Rôle |
|--------|------|
| `EnvironmentService.java` | Orchestre le déploiement : validation GitHub, création environnement, **appel à `gitLabService.triggerPipeline(...)`**, puis enregistrement en BDD. |
| `GitLabService.java` | **Lance le pipeline** via l’API GitLab (POST `/projects/{id}/pipeline`) avec les variables. |
| `EnvironmentController.java` | Expose l’endpoint (ex. POST deploy) qui reçoit la requête du frontend. |
| `DeployRequest.java` | DTO : `gitRepositoryUrl`, `branch`, `githubToken`, `dockerfilePath`, etc. |

### 1.3 Flux de lancement pas à pas

1. L’utilisateur déclenche un déploiement depuis le frontend (URL repo GitHub, branche, token optionnel).
2. **EnvironmentService.deploy()** :
   - Valide le repo GitHub (optionnel si token fourni) via `GitHubValidationService`.
   - Crée ou récupère l’**Application** (avec token GitHub chiffré en BDD).
   - Crée l’**EphemeralEnvironment**.
   - Appelle **GitLabService.triggerPipeline(...)** avec : `gitRepoUrl`, `branch`, `envId`, `applicationId`, `dockerfilePath`.
3. **GitLabService.triggerPipeline()** :
   - Récupère le token GitHub déchiffré via `ApplicationService.getDecryptedGithubToken(applicationId)`.
   - Construit le corps de la requête : `ref` = branche du projet GitLab (ex. `master`), `variables` = tableau avec `GIT_REPO_URL`, `GIT_BRANCH`, `GITHUB_TOKEN`, `ENVIRONMENT_ID`, `DOCKERFILE_PATH`, `SKIP_DEPLOYMENT`, etc.
   - Envoie un **POST** à :  
     `{gitlab.api-url}/projects/{gitlab.project-id}/pipeline`  
     avec header `PRIVATE-TOKEN: {gitlab.token}` (API GitLab).
   - GitLab répond avec l’objet pipeline (contient `id`, `web_url`, `status`, etc.).
4. Le backend crée une **PipelineExecution** en base avec **`gitlabPipelineId = pipeline.getId()`** (voir section 2).

Référence dans le code :

```87:106:DevSecOpsPlatform_Backend/src/main/java/com/backend/devsecopsplatform_backend/service/environment/EnvironmentService.java
        // 4. Déclencher le pipeline GitLab (token déchiffré, variables: GIT_REPO_URL, GIT_BRANCH, GITHUB_TOKEN, DOCKERFILE_PATH)
        Pipeline pipeline = gitLabService.triggerPipeline(
                request.getGitRepositoryUrl(),
                request.getBranch(),
                env.getId().toString(),
                app.getId(),
                app.getDockerfilePath()
        );

        // 5. Enregistrer l'exécution du pipeline
        PipelineExecution execution = new PipelineExecution();
        execution.setEnvironment(env);
        execution.setGitlabPipelineId(pipeline.getId()); // Long au lieu de intValue()
        ...
        pipelineExecutionRepository.save(execution);
```

---

## 2. Pourquoi l’ID de pipeline en PostgreSQL est le même que dans GitLab

L’ID affiché et stocké côté plateforme est **l’ID du pipeline GitLab**, pas un ID généré par notre base.

- Lors du **trigger**, GitLab retourne un objet pipeline avec un **`id`** (Long). Ce même `id` est enregistré dans la table **`pipeline_executions`** dans la colonne **`gitlab_pipeline_id`**.
- On ne génère **pas** d’autre identifiant pour le pipeline : on utilise systématiquement **`pipeline.getId()`** (GitLab) comme référence.

Fichiers concernés :

| Fichier | Rôle |
|--------|------|
| `PipelineExecution.java` | Entité avec `Long gitlabPipelineId` (colonne `gitlab_pipeline_id`). |
| `PipelineExecutionRepository.java` | `findByGitlabPipelineId(Long gitlabPipelineId)` pour retrouver une exécution à partir de l’ID GitLab. |
| `EnvironmentService.java` | `execution.setGitlabPipelineId(pipeline.getId())` après `triggerPipeline()`. |
| `GitLabService.java` | `mapToPipeline(res)` lit `id` dans la réponse JSON de l’API GitLab et le met dans l’objet `Pipeline`. |

Résultat : **l’ID en base = ID GitLab**. Quand le frontend ou l’API demande le détail du pipeline « 12345 », on utilise 12345 pour interroger à la fois la BDD (`findByGitlabPipelineId(12345)`) et l’API GitLab (récupération statut, jobs, artifacts).

---

## 3. Comment GitLab utilise les variables passées par l'utilisateur (sans modifier le .gitlab-ci.yml)

### 3.1 Principe : variables d'environnement, pas modification du fichier

**GitLab ne modifie PAS le fichier `.gitlab-ci.yml`**. Le fichier reste inchangé dans le dépôt GitLab. À la place, les variables sont passées comme **variables d'environnement** au pipeline lors de son déclenchement.

### 3.2 Comment ça fonctionne

1. **Le fichier `.gitlab-ci.yml`** définit des variables par défaut (souvent vides) :
   ```yaml
   variables:
     GIT_REPO_URL: ""
     GIT_BRANCH: "main"
     GITHUB_TOKEN: ""
     ENVIRONMENT_ID: ""
   ```

2. **Les jobs utilisent ces variables** via la syntaxe shell `$VARIABLE_NAME` :
   ```yaml
   script:
     - echo "Repository = $GIT_REPO_URL"
     - git clone --branch "$GIT_BRANCH" "$GIT_REPO_URL"
   ```

3. **Lors du trigger du pipeline** (via `GitLabService.triggerPipeline()`), le backend envoie un tableau de variables qui **écrasent** les valeurs par défaut :
   ```json
   {
     "ref": "master",
     "variables": [
       { "key": "GIT_REPO_URL", "value": "https://github.com/user/repo" },
       { "key": "GIT_BRANCH", "value": "main" },
       { "key": "GITHUB_TOKEN", "value": "ghp_xxx..." },
       { "key": "ENVIRONMENT_ID", "value": "uuid-123" },
       { "key": "DOCKERFILE_PATH", "value": "./Dockerfile" }
     ]
   }
   ```

4. **GitLab injecte ces variables** comme variables d'environnement dans chaque job du pipeline. Les jobs peuvent alors utiliser `$GIT_REPO_URL`, `$GITHUB_TOKEN`, etc., avec les valeurs fournies par l'utilisateur.

### 3.3 Exemple concret

Dans le fichier `.gitlab-ci.yml` du projet GitLab (`amanibennaceur-group/EnviroTest`), le job `clone-repository` fait :
```yaml
script:
  - echo "Repository = $GIT_REPO_URL"
  - git clone --branch "$GIT_BRANCH" "$AUTH_URL" user-repo
```

Quand le backend envoie `GIT_REPO_URL=https://github.com/user/mon-repo` et `GIT_BRANCH=develop`, GitLab exécute le job avec ces valeurs, **sans modifier le fichier `.gitlab-ci.yml`**.

**Résumé** : Le `.gitlab-ci.yml` reste statique. Les données utilisateur sont injectées comme variables d'environnement au moment du trigger, et chaque job les utilise via `$VARIABLE_NAME`.

---

## 4. Page « Détails du pipeline » : avec ou sans webhook ?

### 3.1 Affichage des détails : **sans** webhook (API GitLab uniquement)

Pour **afficher** le détail d’un pipeline (statut, jobs, stages, rapports de sécurité), le backend **ne s’appuie pas sur le webhook**. Il utilise uniquement l’**API GitLab** à la demande :

- **GET /api/pipelines/{pipelineId}** ou **GET /api/pipelines/by-environment/{envId}** → le contrôleur appelle :
  - `gitLabService.getPipelineSummary(pipelineId)` → appels API GitLab (pipeline + jobs),
  - `gitLabService.getAllSecurityReports(pipelineId)` → téléchargement des artifacts (rapports JSON) via l’API GitLab.

Donc : **la page « détails du pipeline » est alimentée par des appels directs à l’API GitLab**, pas par les données du webhook.

### 4.2 Rôle du webhook : **mise à jour du statut en BDD**

Le webhook GitLab sert à **tenir à jour** l’entité **PipelineExecution** en base (statut, `finished_at`) lorsque GitLab envoie un événement « pipeline » (création, mise à jour, fin).

- **GitLabWebhookController** : `POST /api/webhooks/gitlab` (ou `/projet/api/webhooks/gitlab` selon `context-path`).
- Quand `object_kind == "pipeline"`, on lit `object_attributes.id` (= ID pipeline GitLab) et `object_attributes.status`, puis on fait `findByGitlabPipelineId(pipelineId)` et on met à jour `PipelineExecution.status` et éventuellement `finished_at`.
- Ainsi, les listes (environnements, pipelines) qui lisent la BDD peuvent afficher un statut à jour **sans** que le frontend appelle l’API GitLab à chaque fois.

Fichier webhook :

```51:69:DevSecOpsPlatform_Backend/src/main/java/com/backend/devsecopsplatform_backend/controller/webhook/GitLabWebhookController.java
            if ("pipeline".equals(objectKind)) {
                JsonNode attrs = root.path("object_attributes");
                long pipelineId = attrs.path("id").asLong(0);
                String statusStr = attrs.path("status").asText(null);
                if (pipelineId > 0 && statusStr != null) {
                    Optional<PipelineExecution> opt = pipelineExecutionRepository.findByGitlabPipelineId(pipelineId);
                    if (opt.isPresent()) {
                        PipelineExecution execution = opt.get();
                        execution.setStatus(PipelineStatus.fromGitLabStatus(statusStr));
                        ...
                        pipelineExecutionRepository.save(execution);
                    }
                }
            }
```

### 4.3 Utilisation du webhook par le frontend (analyse détaillée)

**Le webhook EST utilisé indirectement par le frontend**, mais uniquement pour les **listes** (statut des pipelines), pas pour les détails complets.

#### 4.3.1 Endpoints qui utilisent les données mises à jour par le webhook

1. **GET /api/environments** (liste des environnements) :
   - Appelé par : `EnvironmentService.getMyEnvironments()`
   - Lit depuis la BDD : `findFirstByEnvironmentOrderByCreatedAtDesc(env)`
   - Retourne : `latestPipelineStatus = latest.getStatus().name()` ← **Cette valeur vient de la BDD mise à jour par le webhook**
   - Utilisé par le frontend : `EnvironmentService` → affiche le statut du dernier pipeline dans la liste des environnements

2. **GET /api/pipelines** (liste de tous les pipelines) :
   - Appelé par : `PipelineController.listPipelines()`
   - Lit depuis la BDD : `findByEnvironmentInOrderByCreatedAtDesc(envs)`
   - Retourne : `pipelineStatus = execution.getStatus().name()` ← **Cette valeur vient de la BDD mise à jour par le webhook**
   - Utilisé par le frontend : `PipelineService.listPipelines()` → `PipelinesListComponent` affiche le statut dans la liste

#### 4.3.2 Endpoints qui n'utilisent PAS le webhook (appel direct API GitLab)

1. **GET /api/pipelines/{pipelineId}** ou **GET /api/pipelines/by-environment/{envId}** (détails complets) :
   - Appelle directement : `gitLabService.getPipelineSummary(pipelineId)` → API GitLab
   - Appelle directement : `gitLabService.getAllSecurityReports(pipelineId)` → API GitLab
   - **N'utilise PAS** les données de la BDD pour le statut/jobs/stages (sauf en fallback si l'API GitLab échoue)

#### 4.3.3 Résumé de l'utilisation du webhook

| Endpoint | Utilise le webhook ? | Comment |
|----------|---------------------|---------|
| `GET /api/environments` | ✅ **OUI** | Lit `latestPipelineStatus` depuis la BDD (mise à jour par webhook) |
| `GET /api/pipelines` | ✅ **OUI** | Lit `pipelineStatus` depuis la BDD (mise à jour par webhook) |
| `GET /api/pipelines/{pipelineId}` | ❌ **NON** | Appelle directement l'API GitLab pour tout |
| `GET /api/pipelines/by-environment/{envId}` | ❌ **NON** | Appelle directement l'API GitLab pour tout (sauf fallback) |

**Conclusion** :
- Le webhook **EST utilisé** : il met à jour la BDD, et les **listes** (environnements, pipelines) lisent cette BDD pour afficher le statut à jour sans appeler l'API GitLab.
- Le webhook **N'EST PAS utilisé** pour les détails complets (jobs, stages, rapports) : ces données viennent toujours directement de l'API GitLab.

**Avantage** : Les listes sont plus rapides (lecture BDD locale) et le statut est à jour grâce au webhook. Les détails restent toujours synchronisés avec GitLab via l'API.

En résumé :

- **Affichage détaillé (détails du pipeline)** → **API GitLab** (getPipelineSummary, getPipelineJobs, getAllSecurityReports).
- **Mise à jour du statut en BDD** → **Webhook GitLab** (optionnel mais utile pour cohérence listes / statut).
- **Affichage des listes (statut)** → **BDD mise à jour par le webhook** (plus rapide que d'appeler l'API GitLab pour chaque pipeline).

---

## 5. Comment on obtient le même résultat pour chaque stage (jobs)

Les « stages » côté GitLab sont des **jobs** définis dans le `.gitlab-ci.yml` du projet GitLab (ex. clone, build, dependency-scan, image-scan, sast). Le backend **ne définit pas** les stages ; il **interroge** GitLab pour les obtenir.

### 4.1 Connaître les stages et le résultat de chaque job

- **getPipelineJobs(pipelineId)** (GitLabService) : appelle l’API GitLab  
  `gitLabApi.getJobApi().getJobsForPipeline(gitlabProjectId, pipelineId)`  
  et retourne la liste des **Job** (chacun a un nom, un statut, un stage, une durée, une webUrl, etc.).
- **getPipelineSummary(pipelineId)** construit une map qui inclut :
  - infos pipeline (statut, webUrl, duration, ref, sha),
  - **jobStatusCount** (nombre de jobs par statut),
  - **jobs** : liste de maps avec pour chaque job : `id`, `name`, `status`, `stage`, `duration`, `webUrl`.

Donc le **même résultat** (nom du job, stage, statut, durée) que sur GitLab est obtenu en **relayant** la réponse de l’API GitLab (jobs du pipeline). Les stages sont ceux renvoyés par GitLab (`job.getStage()`), donc conformes au `.gitlab-ci.yml`.

Fichier :

```611:424:DevSecOpsPlatform_Backend/src/main/java/com/backend/devsecopsplatform_backend/service/GitLabService.java
    public Map<String, Object> getPipelineSummary(Long pipelineId) {
        ...
            Pipeline pipeline = getPipeline(pipelineId);
            List<Job> jobs = getPipelineJobs(pipelineId);
            ...
            for (Job job : jobs) {
                Map<String, Object> jobInfo = new HashMap<>();
                jobInfo.put("id", job.getId());
                jobInfo.put("name", job.getName());
                jobInfo.put("status", job.getStatus().toString());
                jobInfo.put("stage", job.getStage());
                jobInfo.put("duration", job.getDuration());
                jobInfo.put("webUrl", job.getWebUrl());
                jobsList.add(jobInfo);
            }
            summary.put("jobs", jobsList);
```

### 4.2 Rapports de sécurité (résultat « détaillé » par stage)

Pour les jobs de scan (dépendances, image, SAST), le backend récupère les **artifacts** (fichiers JSON) générés par ces jobs :

- **getAllSecurityReports(pipelineId)** :
  - appelle **getPipelineJobs(pipelineId)**,
  - pour chaque job dont le nom correspond (ex. `dependency-scan`, `image-scan`, `sast`) et le statut est SUCCESS,
  - télécharge l’artifact (ex. `trivy-dependencies-report.json`, `trivy-image-report.json`, `sonarqube-report.json`) via **getSecurityReport(jobId, reportFileName)**,
  - qui utilise **downloadJobArtifact(jobId, path)** (API GitLab : GET `/projects/{id}/jobs/{job_id}/artifacts/{path}`).

Ainsi, le « résultat » de chaque stage de scan est le **même** que sur GitLab : ce sont les mêmes fichiers JSON téléchargés depuis les jobs GitLab.

---

## 6. Envoyer des données vers GitLab (API utilisée)

Tout se fait via l’**API REST GitLab** (v4), soit avec **RestTemplate**, soit avec la lib **GitLab4J** (qui appelle la même API).

### 5.1 Envoi pour lancer le pipeline

- **Méthode** : POST.
- **URL** : `{gitlab.api-url}/projects/{gitlab.project-id}/pipeline`  
  (ex. `https://gitlab.com/api/v4/projects/79441224/pipeline`).
- **Headers** : `Content-Type: application/json`, `PRIVATE-TOKEN: {gitlab.token}`.
- **Body** : JSON avec `ref` (branche du projet GitLab) et `variables` (tableau de `{ "key", "value" }`) :  
  `GIT_REPO_URL`, `GIT_BRANCH`, `GITHUB_TOKEN`, `ENVIRONMENT_ID`, `DOCKERFILE_PATH`, `SKIP_DEPLOYMENT`.

Fichier : `GitLabService.triggerPipeline()` (RestTemplate + `rest.exchange(url, HttpMethod.POST, entity, Map.class)`).

### 5.2 Autres envois (API GitLab)

- **Annulation** : `gitLabApi.getPipelineApi().cancelPipelineJobs(gitlabProjectId, pipelineId)`.
- **Retry** : `gitLabApi.getPipelineApi().retryPipelineJob(gitlabProjectId, pipelineId)`.

Configuration : `application.properties` (ou variables d’environnement) : `gitlab.api-url`, `gitlab.project-id`, `gitlab.token`.

---

## 7. Recevoir des données depuis GitLab

### 6.1 Réception « à la demande » (API GitLab)

Le backend **ne reçoit pas** les données en continu ; il **interroge** l’API GitLab quand il en a besoin (par exemple quand l’utilisateur ouvre la page de détail d’un pipeline).

Appels utilisés :

| Donnée | Méthode / API | Fichier / méthode |
|--------|----------------|-------------------|
| Pipeline (statut, durée, webUrl, ref, sha) | GET pipeline | `GitLabService.getPipeline()` → `gitLabApi.getPipelineApi().getPipeline(...)` |
| Liste des jobs (nom, stage, statut, durée, id) | GET jobs du pipeline | `GitLabService.getPipelineJobs()` → `gitLabApi.getJobApi().getJobsForPipeline(...)` |
| Logs d’un job | GET trace du job | `GitLabService.getJobLogs()` → `gitLabApi.getJobApi().getTrace(...)` |
| Artifact (rapport JSON) | GET artifact du job | `GitLabService.downloadJobArtifact()` → RestTemplate GET `.../jobs/{jobId}/artifacts/{path}` |
| Résumé pipeline + jobs | Combinaison des deux premiers | `GitLabService.getPipelineSummary()` |
| Tous les rapports de sécurité | Jobs + download artifact par job de scan | `GitLabService.getAllSecurityReports()` |

Donc : **réception = appels GET (ou téléchargement d’artifacts) à l’API GitLab**, déclenchés par les endpoints du backend (PipelineController, EnvironmentService).

### 6.2 Réception « en push » (webhook GitLab)

GitLab **envoie** des requêtes HTTP **vers** notre backend quand un événement pipeline se produit (création, mise à jour, fin).

- **URL** à configurer dans GitLab : `http(s)://<notre-serveur>:8089/projet/api/webhooks/gitlab`.
- **Événement** : Pipeline events.
- **Corps** : JSON avec `object_kind: "pipeline"` et `object_attributes` (id, status, finished_at, …).
- Le backend reçoit ce JSON dans **GitLabWebhookController.gitlabWebhook()**, met à jour **PipelineExecution** en base (statut, `finished_at`), puis répond 200.

Aucune autre donnée (jobs, logs, artifacts) n’est reçue par webhook ; elles sont toujours récupérées via l’API GitLab.

---

## 8. Récapitulatif des fichiers utilisés

| Fichier | Rôle |
|--------|------|
| **EnvironmentService.java** | Déploiement : validation GitHub, création env, appel triggerPipeline, sauvegarde PipelineExecution avec gitlabPipelineId. |
| **GitLabService.java** | Trigger pipeline (POST), getPipeline, getPipelineJobs, getPipelineSummary, getJobLogs, downloadJobArtifact, getSecurityReport, getAllSecurityReports, cancelPipeline, retryPipeline. |
| **PipelineController.java** | GET list pipelines, GET by env, GET by pipelineId, GET job logs, GET job scan, POST cancel. Pour le détail : appelle getPipelineSummary + getAllSecurityReports (API GitLab). |
| **GitLabWebhookController.java** | Réception webhook GitLab ; mise à jour statut + finished_at de PipelineExecution en BDD. |
| **PipelineExecution.java** | Entité : gitlabPipelineId, status, environment, startedAt, finishedAt. |
| **PipelineExecutionRepository.java** | findByGitlabPipelineId, findFirstByEnvironmentOrderByCreatedAtDesc, etc. |
| **PipelineScanResponse.java** | DTO : pipelineId, status, webUrl, jobStatusCount, jobs, securityReports. |
| **DeployRequest.java** / **DeployResponse.java** | Requête/réponse déploiement (gitlabPipelineId, pipelineWebUrl, etc.). |
| **application.properties** | gitlab.api-url, gitlab.project-id, gitlab.token, gitlab.webhook.secret, pipeline.default-branch. |

---

## 9. Schéma de flux simplifié

```
[Frontend] → POST deploy (repo GitHub, branch, token)
    → EnvironmentController
    → EnvironmentService.deploy()
        → GitLabService.triggerPipeline()  →  POST API GitLab /pipeline  →  [GitLab]
        → Réponse GitLab: { id, web_url, status }
        → execution.setGitlabPipelineId(pipeline.getId())
        → pipelineExecutionRepository.save(execution)  →  [PostgreSQL]

[GitLab] (quand le pipeline change)
    → POST /api/webhooks/gitlab  →  GitLabWebhookController
    → findByGitlabPipelineId(pipelineId)  →  update status/finished_at  →  save  →  [PostgreSQL]

[Frontend] → GET /api/pipelines/{pipelineId} ou /by-environment/{envId}
    → PipelineController
    → getPipelineSummary(pipelineId)       →  GET API GitLab (pipeline + jobs)
    → getAllSecurityReports(pipelineId)    →  GET API GitLab (artifacts des jobs de scan)
    → PipelineScanResponse (jobs, status, securityReports)
```

---

*Document généré pour le projet DevSecOps Platform – Backend.*
