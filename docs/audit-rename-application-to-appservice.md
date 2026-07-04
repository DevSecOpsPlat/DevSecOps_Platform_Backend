# Rapport d'audit — Rename `Application` → `AppService` (lecture seule)

**Date :** 3 juillet 2026  
**Périmètre :** `DevSecOpsPlatform_Backend` (+ références front consommées).  
**Décisions auditées :** rename symbolique de `entity.Application` → `AppService` ; suppression `entity.appmgmt.AppService`, `ManagedApplication`, `AppDeployment` ; rattachement des enfants (`ServiceEnvVar`, `AppDatabase`, …) à la classe renommée ; **aucune migration de schéma** ; `@Table(name="applications")` et `@Column(name=...)` inchangés ; `gitRepositoryUrl` reste `nullable=false`.

---

## Synthèse exécutive

| Zone | Verdict |
|------|---------|
| Collision de nom `AppService` | **Bloquante** — 2 classes homonymes dans 2 packages ; **impossible de coexister** après rename |
| Références type `Application` | **~120+ occurrences** dans **17 fichiers Java** (hors faux positifs Spring/MediaType) |
| JPQL `FROM Application` | **11 requêtes** dans `ApplicationRepository` — **cassent** sans `@Entity(name="Application")` |
| Chaînes `mappedBy` / JSON | **~15 chaînes** à auditer ; risque `MappingException` Hibernate au boot |
| Schéma BDD vs décisions | **Incohérence majeure** — FK V6 pointent vers `dep_application` / `app_service`, pas `applications` |
| Routes API | **`/api/applications`** doit rester ; module **`/api/managed-applications`** à supprimer/remplacer |
| DefectDojo / pipeline | **Indépendant du nom de classe** — dérivé de `gitRepositoryUrl`, `applicationId` UUID, tag `env-<uuid>` |

### Alerte modèle de données (bloquant conceptuel)

Les décisions actuelles entrent en **contradiction** avec l'état réel du code et de la BDD :

| Entité actuelle | Table | FK cible actuelle |
|-----------------|-------|-------------------|
| `Application` (legacy) | `applications` | — |
| `appmgmt.AppService` | `app_service` | `dep_application(id)` |
| `AppDatabase` | `app_database` | `dep_application(id)` |
| `ServiceEnvVar` | `service_env_var` | `app_service(id)` |

Si on **supprime** `appmgmt.AppService` et on **renomme** `Application` → `AppService` sur la table `applications`, on **perd** les colonnes `role`, `exposed_port`, `replicas`, `depends_on_*`, etc. (elles sont sur `app_service`, pas sur `applications`).  
Rattacher `ServiceEnvVar` à la classe renommée **sans migration** implique que `service_env_var.app_service_id` référence `applications.id` — **contrainte FK actuelle invalide** (référence `app_service.id`).

`docs/prompt_migration.md` décrit une voie différente : **garder `Application` comme conteneur** + enfants `AppService` sur `app_service` avec FK vers `applications(id)`. La décision actuelle (rename `Application` → `AppService`) est **l'inverse** de ce document.

---

## §1 — Collision de noms `AppService`

### 1.1 Les deux classes homonymes

| Classe | Package | Table | Rôle |
|--------|---------|-------|------|
| **À renommer** | `entity.Application` | `applications` | 1 repo, deploy+scan, `EphemeralEnvironment` parent |
| **À supprimer** | `entity.appmgmt.AppService` | `app_service` | Enfant de `ManagedApplication`, multi-services |

**Verdict coexistence :** **NON.** Après rename, `com.backend...entity.AppService` et `com.backend...entity.appmgmt.AppService` ne peuvent pas coexister. **Ordre obligatoire : supprimer `appmgmt.AppService` AVANT le rename symbolique.**

---

### 1.2 Fichiers référençant `entity.appmgmt.AppService` (à supprimer/migrer)

| Fichier | Ligne(s) | Extrait | Risque | Correction |
|---------|----------|---------|--------|------------|
| `entity/appmgmt/AppService.java` | 32 | `public class AppService` | Définition — collision directe | **Supprimer** après migration logique |
| `repository/AppServiceRepository.java` | 3, 14+ | `JpaRepository<AppService, UUID>` | Collision avec futur repo legacy | Supprimer ; futur `AppServiceRepository` = ex-`ApplicationRepository` |
| `entity/appmgmt/ServiceEnvVar.java` | 37 | `private AppService appService` | FK enfant | Rebrancher vers `entity.AppService` (renommé) |
| `service/appmgmt/ApplicationManagementService.java` | 92, 107, 356-357 | `svc.setApplication(app)`, `getAppService()` | Logique appmgmt | Supprimer module ou réécrire sur `ApplicationService` |
| `service/appmgmt/AppK8sManifestService.java` | 4-5, 312+ | `AppService svc`, `ManagedApplication app` | Générateur K8s | Migrer vers service unifié ou supprimer |
| `service/appmgmt/AppDeploymentValidationService.java` | 4-5, 29 | `validate(ManagedApplication app)` | Validation | Migrer / supprimer |
| `service/appmgmt/AppDeploymentService.java` | 6, 242+ | `List<AppService>`, `computeWaves` | Pipeline deploy | Migrer vers `EphemeralEnvironment` (cf. `prompt_migration.md`) |
| `controller/appmgmt/AppServiceRequest.java` | 3 | `AppServiceRole` | DTO — nom OK | Renommer si besoin (`ServiceCompositionRequest` ?) |
| `controller/appmgmt/AppServiceResponse.java` | 3 | idem | DTO | idem |

**DTOs nommés `AppService*` (31 fichiers module `appmgmt/`)** — collision sémantique avec l'entité renommée ; à renommer lors de la fusion.

---

### 1.3 Fichiers référençant `ManagedApplication` / `AppDeployment` (à supprimer)

| Fichier | Risque | Correction |
|---------|--------|------------|
| `entity/appmgmt/ManagedApplication.java` | Table `dep_application` | Supprimer entité + table orpheline (ou migration DROP) |
| `entity/appmgmt/AppDeployment.java` | Table `app_deployment` | Supprimer |
| `entity/appmgmt/AppDeploymentStatus.java` | Enum deploy | Supprimer ou fusionner dans `EnvironmentStatus` |
| `repository/ManagedApplicationRepository.java` | Repo | Supprimer |
| `repository/AppDeploymentRepository.java` | `findByApplication_Id` | Supprimer |
| `service/appmgmt/ApplicationManagementService.java` | Service CRUD complet | Supprimer / fusionner dans `ApplicationService` |
| `service/appmgmt/AppDeploymentService.java` | Orchestration deploy | Migrer vers `EnvironmentService` + `EphemeralEnvironment` |
| `service/appmgmt/AppDeploymentGitLabService.java` | Trigger GitLab | Migrer |
| `controller/appmgmt/ApplicationManagementController.java` | `/api/managed-applications` | Supprimer ; endpoints → `/api/applications/{id}/...` |
| `controller/appmgmt/ManagedDeploymentWebhookController.java` | Callback deploy | Migrer webhook ou supprimer |
| `controller/appmgmt/ManagedAppResponse.java` | DTO | Supprimer |
| `controller/appmgmt/AppDeploymentResponse.java` | DTO | Supprimer |
| `db/migration/V6__app_management.sql` | Schéma `dep_application`, `app_deployment` | **Incohérent** avec « pas de migration » + abandon ManagedApplication |

---

### 1.4 Entités enfants — `@ManyToOne` actuel et rebranchage

| Enfant | Champ FK | Cible actuelle | `mappedBy` parent | Rebranchage cible |
|--------|----------|----------------|-------------------|-------------------|
| `ServiceEnvVar` | `appService` → `app_service_id` | `appmgmt.AppService` | `appmgmt.AppService.envVars` : `mappedBy="appService"` | → `entity.AppService` (renommé) ; **FK DB à corriger** |
| `AppDatabase` | `application` → `application_id` | `ManagedApplication` | `ManagedApplication.databases` : `mappedBy="application"` | → `entity.AppService` ; **FK DB `dep_application` → `applications`** |
| `AppDeployment` | `application` | `ManagedApplication` | `mappedBy="application"` | **Supprimer** (remplacé par `EphemeralEnvironment`) |
| `appmgmt.AppService` | `application` | `ManagedApplication` | `mappedBy="application"` | **Supprimer** entièrement |
| `EphemeralEnvironment` | `application` | `entity.Application` | `Application.ephemeralEnvironments` : `mappedBy="application"` | **Conserver** — cible = classe renommée `AppService` |

---

## §2 — Toutes les références au type `Application`

**Import explicite `entity.Application` : 8 fichiers**

| # | Fichier | Occurrences type `Application` (estim.) | Usage principal |
|---|---------|----------------------------------------|-----------------|
| 1 | `repository/ApplicationRepository.java` | **~25** | `JpaRepository<Application,UUID>`, retours `List<Application>`, JPQL |
| 2 | `service/application/ApplicationService.java` | **~10** | CRUD, `new Application()`, `mapToResponse(Application)` |
| 3 | `service/qualitygate/QualityGateService.java` | **~20** | Snapshots, Sonar, paramètres `Application app` |
| 4 | `service/defectdojo/DefectDojoService.java` | **~15** | Dashboard, `EngagementContext(Application,...)` |
| 5 | `service/admin/AdminUserService.java` | **~4** | `List<Application>`, `e.getApplication()` |
| 6 | `controller/finding/FindingController.java` | **~5** | `resolveApplicationForEnv`, signatures |
| 7 | `service/SourceSnippetFetcherService.java` | **~2** | `env.getApplication()` |
| 8 | `service/finding/ProjectStackInference.java` | **~2** | `buildBlock(..., Application app, ...)` |

**Références sans import direct (champ type / getter)**

| Fichier | Ligne | Extrait | Risque |
|---------|-------|---------|--------|
| `entity/Application.java` | 26 | `public class Application` | Définition — rename cible |
| `entity/EphemeralEnvironment.java` | 45 | `private Application application` | Type champ FK |
| `entity/User.java` | 100 | `private List<Application> applications` | Collection inverse |
| `service/environment/EnvironmentService.java` | 102+ | `Application app = applicationService...` | Via service, pas import direct |
| `service/finding/FindingIngestionService.java` | 227, 380 | `getApplication()` | Type inféré |
| `service/GitLabService.java` | 41 | `ApplicationService` (service, pas entité) | Pas de collision entité |

**Compte total imports + déclarations type `Application` : ~75–85** (hors commentaires/Javadoc).  
**+ ~35 chemins JPQL/property `e.application` / `env.application`** dans repositories.

**Faux positifs à ne pas toucher :** `ApplicationReadyEvent`, `MediaType.APPLICATION_JSON`, message email « Application-specific password ».

---

## §3 — Chaînes littérales annotations (CRITIQUE)

| Fichier | Ligne | Chaîne actuelle | Rester / Aligner | Nouvelle valeur si aligner |
|---------|-------|-----------------|------------------|----------------------------|
| `entity/Application.java` | 19 | `@Table(name = "applications")` | **RESTER** | — |
| `entity/Application.java` | 20-21 | `idx_app_created_by`, `idx_app_name` | **RESTER** | — |
| `entity/Application.java` | 30-57 | Tous `@Column(name=...)` | **RESTER** | — |
| `entity/Application.java` | 51 | `@JoinColumn(name = "created_by")` | **RESTER** | — |
| `entity/Application.java` | 52 | `@JsonIgnoreProperties({"applications", ...})` | **ALIGNER** si `User.applications` renommé | `{"appServices", ...}` |
| `entity/Application.java` | 61 | `mappedBy = "application"` | **RESTER** (si champ enfant inchangé) | — |
| `entity/Application.java` | 62 | `@JsonManagedReference("app-env")` | **RESTER** | — |
| `entity/EphemeralEnvironment.java` | 24 | `idx_env_application`, `application_id` | **RESTER** | — |
| `entity/EphemeralEnvironment.java` | 43 | `@JoinColumn(name = "application_id")` | **RESTER** | — |
| `entity/EphemeralEnvironment.java` | 44 | `@JsonBackReference("app-env")` | **RESTER** | — |
| `entity/EphemeralEnvironment.java` | 53 | `@JsonIgnoreProperties({..., "applications", ...})` | **ALIGNER** si champ User renommé | `"appServices"` |
| `entity/User.java` | 98 | `mappedBy = "createdBy"` | **RESTER** | — |
| `entity/User.java` | 99 | `@JsonIgnoreProperties("createdBy")` | **RESTER** | — |
| `entity/Complaint.java` | 35 | `"applications"` dans JsonIgnoreProperties | **ALIGNER** si User renommé | `"appServices"` |
| `entity/ComplaintMessage.java` | 36 | idem | **ALIGNER** | idem |
| `entity/appmgmt/ManagedApplication.java` | 25 | `@Table(name = "dep_application")` | **SUPPRIMER** entité | — |
| `entity/appmgmt/ManagedApplication.java` | 64-70 | `mappedBy = "application"` ×3 | **SUPPRIMER** | — |
| `entity/appmgmt/AppService.java` | 26 | `@Table(name = "app_service")` | **SUPPRIMER** ou **réorienter FK** | Conflit avec rename |
| `entity/appmgmt/AppService.java` | 40 | `@JoinColumn(name = "application_id")` | **SUPPRIMER** | — |
| `entity/appmgmt/AppService.java` | 108 | `mappedBy = "appService"` | Migrer vers parent renommé | `mappedBy = "appService"` sur `ServiceEnvVar` |
| `entity/appmgmt/ServiceEnvVar.java` | 35 | `@JoinColumn(name = "app_service_id")` | **RESTER** (nom colonne) | — |
| `entity/appmgmt/AppDatabase.java` | 21 | `@Table(name = "app_database")` | **RESTER** table | — |
| `entity/appmgmt/AppDatabase.java` | 34 | `@JoinColumn(name = "application_id")` | **RESTER** colonne | FK cible → `applications` (**migration DB**) |
| `entity/QualityGateSnapshot.java` | 22, 36 | `application_id` (colonne UUID) | **RESTER** | Pas de relation JPA |

**Recommandation `@Entity(name=...)` sur la classe renommée :**

```java
@Entity(name = "Application")  // préserve TOUS les JPQL "FROM Application"
@Table(name = "applications")
public class AppService { ... }
```

Sans cela : **11 JPQL** + **~20 chemins `env.application`** cassent au runtime.

---

## §4 — Champ `application` dans `EphemeralEnvironment`

### État actuel

`EphemeralEnvironment.java` (l.42-45) :
```java
@ManyToOne(fetch = FetchType.LAZY, optional = false)
@JoinColumn(name = "application_id", nullable = false)
@JsonBackReference("app-env")
private Application application;
```

`Application.java` (l.61-63) :
```java
@OneToMany(mappedBy = "application", cascade = CascadeType.ALL, orphanRemoval = true)
@JsonManagedReference("app-env")
private List<EphemeralEnvironment> ephemeralEnvironments = new ArrayList<>();
```

### Option A — **Garder le nom de champ `application`** (recommandé)

| Avantage | Inconvénient |
|----------|--------------|
| `@JoinColumn(name="application_id")` cohérent | Sémantique « application » vs classe `AppService` |
| `mappedBy="application"` inchangé | |
| Méthodes dérivées Spring Data inchangées | |
| JPQL `e.application` inchangé | |

**Méthodes dérivées à conserver telles quelles :**

| Repository | Méthode |
|------------|---------|
| `EphemeralEnvironmentRepository` | `findByApplication_Id`, `findByApplication_IdAndGitBranch...`, `findByIdAndApplication_Id`, `findByApplicationWithPipeline` |
| `AppDatabaseRepository` (appmgmt) | `findByApplication_Id` → si rebranché, **même nom** si champ `application` |
| `AppDeploymentRepository` | **à supprimer** |

### Option B — Renommer en `appService`

| Impact | Détail |
|--------|--------|
| `mappedBy` parent | `"application"` → `"appService"` |
| Spring Data | `findByApplication_Id` → `findByAppService_Id` (**~8 méthodes**) |
| JPQL | `e.application.id` → `e.appService.id` (**~25 requêtes** dans 4 repositories) |
| Code Java | `getApplication()` / `setApplication()` → partout (**~40 appels**) |
| Lombok helpers | `addEphemeralEnvironment` : `environment.setApplication(this)` → `setAppService` |

**Recommandation : Option A** — moins de casse, colonne DB déjà `application_id`.

---

## §5 — JPQL / `@Query` référençant `Application` ou `e.application`

### 5.1 Nom d'entité JPQL `Application`

**Aucun `@Entity(name = "...")` explicite** dans le projet → le nom JPQL par défaut = **nom de classe Java**.

Après rename `Application` → `AppService` **sans** `@Entity(name="Application")` : **toutes les requêtes ci-dessous échouent**.

### 5.2 Requêtes nommant l'entité `Application` (`ApplicationRepository.java`)

| Ligne | Extrait | Correction |
|-------|---------|------------|
| 105 | `SELECT a FROM Application a WHERE...` | `@Entity(name="Application")` **ou** `FROM AppService` |
| 114 | idem | idem |
| 133 | idem | idem |
| 143 | idem | idem |
| 152 | idem | idem |
| 161 | `LEFT JOIN a.ephemeralEnvironments` | idem |
| 179 | `FROM Application a WHERE a.createdAt` | idem |
| 190 | `COUNT(a) FROM Application a` | idem |
| 198 | `SIZE(a.ephemeralEnvironments)` | idem |
| 206 | `JOIN a.ephemeralEnvironments e` | idem |

### 5.3 Requêtes nommant le chemin `e.application` / `env.application`

| Fichier | Lignes | Extrait |
|---------|--------|---------|
| `EphemeralEnvironmentRepository` | 45, 55, 77, 85 | `e.application.id`, `join fetch e.application` |
| `PipelineExecutionRepository` | 40, 69, 82, 97, 106, 119, 127, 135, 149, 159, 173, 182 | `env.application.id`, `JOIN FETCH env.application` |
| `FindingRepository` | 62, 85, 135 | `env.application.id`, `env2.application.id` |
| `FindingOccurrenceRepository` | 25, 35, 139, 153, 167, 183 | `env.application.id` |

**Ces chemins dépendent du nom du champ Java `application` dans `EphemeralEnvironment`, pas du nom de classe.** Si Option A (§4) : **pas de changement**.

### 5.4 `applicationId` dénormalisé (pas de JPQL entité)

`QualityGateSnapshot.applicationId`, DTOs, controllers — **UUID**, indépendant du rename de classe. **Aucun impact.**

---

## §6 — Endpoints / routes API

### 6.1 Backend — routes existantes (à **GARDER**)

| Contrôleur | Base | Consommateur front |
|------------|------|-------------------|
| `ApplicationController` | `/api/applications` | `ApplicationService` → `GET/POST api/applications`, `GET api/applications/{id}`, deployments |
| `QualityGateController` | `/api/quality-gate` | `?applicationId=` |
| `DefectDojoController` | `/api/defectdojo` | `?applicationId=` |
| `FindingController` | `/api/findings` | `/applications/{appId}/...` |
| `EnvironmentController` | `/api/deploy` ou environnements | deploy flow |

**Recommandation :** le rename de classe **n'impose aucun changement d'URL**. Ne pas renommer `/api/applications` en `/api/app-services`.

### 6.2 Module appmgmt (à supprimer / fusionner)

| Contrôleur | Base | Action |
|------------|------|--------|
| `ApplicationManagementController` | `/api/managed-applications` | Supprimer ; migrer endpoints vers `/api/applications/{id}/services`, `/databases`, etc. |
| `ManagedDeploymentWebhookController` | `/api/webhooks/managed-deployments/{id}/status` | Migrer ou supprimer |

### 6.3 Frontend

| Service / route | URL | Risque si rename backend routes |
|-----------------|-----|--------------------------------|
| `application.service.ts` | `api/applications` | **Casse** si routes changent |
| `application-management.service.ts` | `api/managed-applications` | Module à supprimer/fusionner |
| Routes | `/my-applications`, `/applications`, `/project/:appId` | IDs UUID inchangés |
| Routes | `/app-management` | Liées au module ManagedApplication |

**Les noms de classes TypeScript `ApplicationService` / `ApplicationResponse` sont indépendants du backend** — pas de casse automatique.

---

## §7 — Intégrations externes (DefectDojo, pipeline, logs)

### 7.1 DefectDojo — **indépendant du nom de classe Java**

| Donnée envoyée | Source | Dépend du nom `Application` ? |
|----------------|--------|------------------------------|
| `productName` | `extractRepoName(app.getGitRepositoryUrl())` | **NON** — dérivé URL repo |
| `engagementName` | `productName + "_" + branch` | **NON** |
| Tag environnement | `"env-" + environmentId` (UUID) | **NON** — aligné CI `env-${ENVIRONMENT_ID}` |
| `applicationName` (DTO) | `app.getName()` | **NON** — champ `name`, pas nom de classe |
| `applicationId` (param API) | UUID query param | **NON** |

**Confirmation :** le rename `Application` → `AppService` **ne change rien** côté DefectDojo tant que `gitRepositoryUrl`, `name`, et les UUID restent identiques.

### 7.2 Pipeline GitLab

| Variable | Source | Impact rename |
|----------|--------|---------------|
| `GITHUB_TOKEN` | `applicationService.getDecryptedGithubToken(applicationId)` | **NON** — UUID inchangé |
| `ENVIRONMENT_ID` | UUID env | **NON** |
| `applicationId` (param Java) | UUID | **NON** |

Module deploy appmgmt passe `APP_ID`, `SERVICES_JSON`, etc. — **à migrer** si `AppDeployment` supprimé.

### 7.3 Logs

Messages du type `"Application introuvable"` — cosmétique uniquement, pas d'impact fonctionnel.

---

## Collisions de noms post-rename (hors entités)

| Symbole actuel | Conflit après rename | Action |
|----------------|---------------------|--------|
| `ApplicationRepository` | Futur `AppServiceRepository` existe (appmgmt) | Supprimer appmgmt repo **puis** renommer `ApplicationRepository` → `AppServiceRepository` |
| `ApplicationService` (service) | Pas de collision avec entité | **Garder** le nom (package `service.application`) ou renommer optionnel |
| `ApplicationController` | Pas de collision | Garder routes |
| `ApplicationResponse` (DTO) | Pas de collision entité | Optionnel : `AppServiceResponse` |
| `AppServiceRequest/Response` (appmgmt DTO) | Collision sémantique | Renommer DTOs appmgmt |
| `AppServiceRole` (enum) | OK — enum distinct | Garder |

---

## Risques de démarrage Hibernate (boot)

| Risque | Cause | Symptôme |
|--------|-------|----------|
| **MappingException** | `mappedBy="application"` sans champ correspondant | Boot fail |
| **MappingException** | `ServiceEnvVar.appService` → entité supprimée | Boot fail |
| **AnnotationException** | Deux `@Entity` `AppService` | Compilation fail (avant boot) |
| **FK invalide** | `app_database.application_id` → `dep_application` mais entité pointe `applications` | Boot ou runtime SQL error |
| **Table manquante** | Hibernate `ddl-auto=update` + suppression `app_service` | Perte données / erreurs |
| **JPQL invalide** | `FROM Application` après rename sans `@Entity(name)` | Runtime `QueryException` |

---

## Séquence de rename sûre (ordre recommandé)

```
Phase 0 — Décision schéma (PRÉREQUIS, hors scope « zéro migration »)
  └─ Trancher : prompt_migration.md (Application conteneur + enfants app_service)
     VS rename Application→AppService (1 ligne = 1 service).
  └─ Si « zéro migration » strict : impossible de rattacher AppDatabase/ServiceEnvVar
     sans corriger les FK V6 (dep_application, app_service).

Phase 1 — Suppression module appmgmt (débloque le nom AppService)
  1.1 Supprimer entity.appmgmt.AppService (fichier + table logique)
  1.2 Supprimer ManagedApplication, AppDeployment (+ repos, services, controllers, DTOs)
  1.3 Supprimer ApplicationManagementController, ManagedDeploymentWebhookController
  1.4 Supprimer repository/AppServiceRepository (appmgmt)
  1.5 Vérifier compilation (module appmgmt entièrement retiré)

Phase 2 — Rebrancher les enfants conservés (ServiceEnvVar, AppDatabase)
  2.1 ServiceEnvVar.@ManyToOne → entity.AppService (après rename)
  2.2 AppDatabase.@ManyToOne → entity.AppService (après rename)
  2.3 Ajouter sur classe renommée :
        @OneToMany(mappedBy="appService") List<ServiceEnvVar>
        @OneToMany(mappedBy="application") List<AppDatabase>  // si champ gardé "application"
  2.4 Migration DB : FK app_database.application_id → applications(id)
                   FK service_env_var.app_service_id → applications(id)
     (contredit « aucune migration » — à assumer explicitement)

Phase 3 — Rename symbolique Application → AppService
  3.1 Renommer fichier Application.java → AppService.java
  3.2 Ajouter @Entity(name = "Application") pour préserver JPQL
  3.3 Garder @Table(name = "applications") et tous @Column(name=...) identiques
  3.4 gitRepositoryUrl : conserver nullable=false (décision actée)

Phase 4 — Aligner chaînes littérales (§3)
  4.1 Option A : garder champ EphemeralEnvironment.application → rien
  4.2 Si User.applications renommé appServices → aligner JsonIgnoreProperties
  4.3 Vérifier paires @JsonManagedReference / @JsonBackReference ("app-env")

Phase 5 — Renommer couche persistence (optionnel mais cohérent)
  5.1 ApplicationRepository → AppServiceRepository (interface + injections)
  5.2 Mettre à jour imports dans 8+ services

Phase 6 — Fusionner logique appmgmt dans existant (hors rename)
  6.1 Endpoints composition → ApplicationController (routes inchangées)
  6.2 Deploy → EphemeralEnvironment (pas AppDeployment)
  6.3 Front : supprimer application-management/, fusionner dans project/applications

Phase 7 — Vérifications
  7.1 mvn compile
  7.2 Démarrage Spring → pas de MappingException
  7.3 Smoke : POST /api/applications, deploy, quality-gate ?applicationId=, DefectDojo dashboard
  7.4 Front : /my-applications, /project/:appId/overview
```

---

## Conclusion

Le rename **`Application` → `AppService`** est **faisable côté Java** avec `@Entity(name="Application")` + **Option A** (garder le champ `application` dans `EphemeralEnvironment`), mais **entre en conflit direct** avec :

1. **`entity.appmgmt.AppService`** — suppression **obligatoire avant** le rename ;
2. **`ManagedApplication` / `AppDeployment`** — tout le module `appmgmt/` (31 fichiers) à supprimer ou fusionner ;
3. **Schéma V6** — FK vers `dep_application` / `app_service` **incompatibles** avec « rattacher les enfants à `applications` sans migration » ;
4. **Sémantique produit** — la table `applications` n'a **pas** les colonnes multi-services (`role`, `exposed_port`, etc.) de `app_service`.

**Recommandation architecturale :** avant d'exécuter le rename, trancher entre la décision actuelle (1 row `applications` = 1 service) et `docs/prompt_migration.md` (1 `Application` conteneur + N `app_service` enfants). Les deux modèles impliquent des migrations et des impacts différents.
