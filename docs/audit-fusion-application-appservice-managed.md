# Rapport d'audit — Fusion `Application` → `AppService` + conservation `ManagedApplication`

**Date :** 3 juillet 2026  
**Mode :** lecture seule — aucun fichier modifié  
**Objectif :** garantir que la solution proposée peut être appliquée sans fichier cassé, sans conflit de compilation, sans erreur Hibernate au démarrage.

---

## Plan audité (à appliquer plus tard, pas exécuté ici)

1. Supprimer l'entité `entity.appmgmt.AppService` (table `app_service`) et son repository.
2. Renommer `entity.Application` (table `applications`, reliée au scan Sonar/DefectDojo) → `AppService`, en gardant `@Table(name="applications")` et en ajoutant `@Entity(name="Application")`.
3. Fusionner dans cette `AppService` renommée les attributs multi-services de l'ancienne `appmgmt.AppService` (`role`, `exposed_port`, `git_branch`, `build_context`, `depends_on_service_id`, `depends_on_database_id`, `db_url_env_var`, `replicas`, `health_check_path`, `cpu_*`, `memory_*`, `git_token` chiffré) + une FK `managed_application_id`. Tous nullable.
4. Garder `ManagedApplication` comme conteneur/projet : `List<AppService> services`.
5. Rebrancher `ServiceEnvVar` et `AppDatabase` vers la nouvelle `AppService` / `ManagedApplication`.
6. Garder le champ `EphemeralEnvironment.application` (nom inchangé, type devient `AppService`).
7. Migration SQL : `ADD COLUMN` sur `applications`, rebranchage FK des enfants, `DROP app_service`.

---

## Contexte technique confirmé

| Paramètre | Valeur réelle | Source |
|---|---|---|
| `ddl-auto` | **`update`** | `application.properties:13` |
| Flyway | actif, `baseline-on-migrate=true`, `baseline-version=0` | `application.properties:16-17` |
| Migrations existantes | V1→V6 | `db/migration/` |
| `@Entity(name=...)` existant | **aucun** | recherche globale |
| Lombok sur `Application` | `@Data @NoArgsConstructor @AllArgsConstructor` | `Application.java` |

---

## Bloc A — Inventaire exhaustif des fichiers reliés à l'ex-`Application`

### A.1 Import direct `entity.Application` (8 fichiers)

| Fichier | Ligne | Type dépendance | Sera modifié comment | Risque résiduel |
|---|---|---|---|---|
| `repository/ApplicationRepository.java` | 3, 19, 27-207 | `JpaRepository<Application,UUID>` + 11 JPQL | rename type → `AppService` ; `@Entity(name="Application")` sauve les JPQL | **Nul si `@Entity(name)` ajouté** |
| `service/application/ApplicationService.java` | 5, 58, 128 | import + `new Application()` ×2 | rename type | Nul (constructeurs no-arg) |
| `service/qualitygate/QualityGateService.java` | 3, ~20 sig. | import + params `Application app` | rename type | Nul (dépend de getters, pas du nom) |
| `service/defectdojo/DefectDojoService.java` | 4, 56, 726, 2031, 2043 | import + record `EngagementContext(Application,…)` positionnel | rename type (même fichier → auto) | Nul |
| `service/admin/AdminUserService.java` | 7, 180, 395, 437 | import + `List<Application>` | rename type | Nul |
| `controller/finding/FindingController.java` | 8, 157, 210, 230-236 | import + `resolveApplicationForEnv` | rename type | Nul |
| `service/SourceSnippetFetcherService.java` | 3, 75, 79 | import + `env.getApplication()` | rename type | Nul |
| `service/finding/ProjectStackInference.java` | 3, 20, 33 | import + `buildBlock(...,Application,...)` | rename type | Nul (garde `nullToEmpty`) |

### A.2 Type `Application` sans import (champ / getter)

| Fichier | Ligne | Détail | Sera modifié comment | Risque résiduel |
|---|---|---|---|---|
| `entity/EphemeralEnvironment.java` | 45 | `private Application application` | rename type → `AppService` ; **nom de champ conservé** | Nul |
| `entity/User.java` | 100 | `private List<Application> applications` | rename type ; `mappedBy="createdBy"` figé | Nul |
| `service/environment/EnvironmentService.java` | 102, 115, 230-405 | `Application app = …`, `e.getApplication()` | rename type | Nul |
| `service/finding/FindingIngestionService.java` | 227, 380 | `getApplication()` inféré (`var`) | rename type | Nul |

### A.3 `new Application(...)` — analyse constructeurs

| Fichier | Ligne | Forme | Risque avec nouveaux champs |
|---|---|---|---|
| `ApplicationService.java` | 58, 128 | `new Application()` **no-arg** + setters | **Aucun** — l'ajout de champs ne casse pas le no-arg |

**Conclusion :** aucun `new Application(...)` positionnel. L'`@AllArgsConstructor` verra sa signature grossir mais personne ne l'appelle positionnellement → pas de casse.

### A.4 Généricité

`List<Application>`, `Optional<Application>`, `JpaRepository<Application,UUID>` : uniquement dans `ApplicationRepository` + `AdminUserService` + `ApplicationService`. Tous couverts par le rename symbolique. **Pas de `Page<Application>`.**

### A.5 JPQL / chemins `x.application`

| Fichier | Lignes | Contenu | Action |
|---|---|---|---|
| `ApplicationRepository` | 105,114,133,143,152,161,179,190,198,206 | `FROM Application a` (11) | **Sauvés par `@Entity(name="Application")`** |
| `EphemeralEnvironmentRepository` | 45,55,77,85 | `e.application.id` | Inchangé (nom de champ conservé) |
| `PipelineExecutionRepository` | 40,69,82,97,106,119,127,135,149,159,173,182 | `env.application.id` | Inchangé |
| `FindingRepository` | 62,85,135 | `env.application.id` | Inchangé |
| `FindingOccurrenceRepository` | 25,35,139,153,167,183 | `env.application.id` | Inchangé |

### A.6 Méthodes dérivées Spring Data (nom de champ `application` conservé → intactes)

- `EphemeralEnvironmentRepository.findByApplication_Id`
- `EphemeralEnvironmentRepository.findByApplication_IdAndGitBranch…`
- `EphemeralEnvironmentRepository.findByIdAndApplication_Id`

### A.7 DTO / mappers listant les champs de `Application`

| Fichier | Ligne | Détail | Action | Risque |
|---|---|---|---|---|
| `controller/application/ApplicationResponse.java` | — | Builder par champ (`name`, `gitRepositoryUrl`, …) | Aucun (pas de constructeur positionnel entité) | Nul |
| `service/application/ApplicationService.java` | 160 | `mapToResponse(Application)` via builder | Rename type paramètre | Nul |

---

## Bloc B — Vérification « aucun conflit après modification »

### B.1 `new Application(...)` positionnels

**Aucun.** Les deux instanciations utilisent le constructeur no-arg + setters. ✅

### B.2 Getters ambigus

`getGitRepositoryUrl()` reste unique sur l'entité renommée. Les familles d'appels (`DefectDojo`, `SonarProjectKeyUtil`, `SourceSnippet`) opèrent sur l'entité renommée ou sur `EphemeralEnvironment.getApplication()`. **Aucune ambiguïté.**

### B.3 Collisions résiduelles après suppression de `appmgmt.AppService`

| Symbole | Après suppression | Verdict |
|---|---|---|
| `entity.AppService` (renommé) vs `entity.appmgmt.AppService` | 2ᵉ supprimé | ✅ plus de collision de type |
| `ApplicationRepository` vs `appmgmt.AppServiceRepository` | 2ᵉ supprimé | ✅ (⚠️ si renommage `ApplicationRepository`→`AppServiceRepository`, faire **après** suppression) |
| `AppServiceRole` (enum, `appmgmt`) | conservé | ✅ pas de collision |
| DTO `AppServiceRequest/Response` (`appmgmt`) | conservés | ✅ noms distincts de l'entité |

### B.4 Chaînes littérales — à aligner vs figées

| Fichier | Ligne | Chaîne | Action |
|---|---|---|---|
| `entity/AppService` (ex-Application) | `@Table` | `"applications"` | **FIGÉE** |
| idem | tous `@Column(name)` | | **FIGÉE** |
| idem | 62 | `@JsonManagedReference("app-env")` | **FIGÉE** (paire avec `EphemeralEnvironment:44`) |
| idem | 61 | `mappedBy="application"` (→ ephemeralEnvironments) | **FIGÉE** (champ enfant inchangé) |
| `ManagedApplication.java` | 64 | `@OneToMany(mappedBy="application") List<AppService>` | **⚠️ À ALIGNER** sur le nom du champ FK ajouté dans `AppService` (ex. `managedApplication`) — sinon **MappingException** |
| `ManagedApplication.java` | 70 | `List<AppDeployment> deployments` | **⚠️ AMBIGU** — voir Bloc C.4 |
| `ServiceEnvVar.java` | 37 | `appService` → type `AppService` | Rebrancher vers `entity.AppService` |
| `EphemeralEnvironment.java` / `User.java` / `Complaint` / `ComplaintMessage` | — | `"applications"` dans `@JsonIgnoreProperties` | **FIGÉE** si `User.applications` garde son nom |

---

## Bloc C — Cohérence base de données / entités

### C.1 FK actuelles et cibles après migration

| FK (colonne) | Cible actuelle | Cible après | Action migration |
|---|---|---|---|
| `service_env_var.app_service_id` | `app_service(id)` | **`applications(id)`** | drop FK + (data) + add FK |
| `app_database.application_id` | `dep_application(id)` | **inchangée** (AppDatabase reste sur ManagedApplication) | aucune |
| `app_deployment.application_id` | `dep_application(id)` | selon C.4 | à trancher |
| **`applications.managed_application_id`** (nouveau) | — | `dep_application(id)` | ADD COLUMN + ADD FK, nullable |
| `applications` (nouvelles colonnes) | — | `applications` | ADD COLUMN role, exposed_port, git_branch, build_context, depends_on_service_id, depends_on_database_id, db_url_env_var, replicas, health_check_path, cpu_*, memory_*, git_token — **toutes nullable** |

### C.2 `ddl-auto=update` + Flyway — risque de perte / validation

- Flyway s'exécute **avant** Hibernate → les colonnes ADD sont présentes quand `update` inspecte. **Pas d'erreur de validation** (ce n'est pas `validate`).
- `update` **n'exécute jamais de DROP** → aucun risque qu'Hibernate supprime des données. Le DROP `app_service` est **uniquement** dans la migration Flyway.
- Colonnes ajoutées **nullable** → pas de violation `NOT NULL` sur lignes existantes. ✅

### C.3 Migrations existantes référençant `app_service` / `dep_application`

| Migration | Référence | Contradiction avec V7 (nouvelle) ? |
|---|---|---|
| `V6` L39-64 | crée `app_service` + FK vers `dep_application` | **Non**, si V7 (> V6) fait le DROP après avoir migré. Ordre Flyway respecté. |
| `V6` L4-17 | crée `dep_application` | conservé (ManagedApplication) ✅ |
| `V6` L66-77 | `service_env_var.app_service_id`→`app_service` | **À corriger en V7** (rebranchage FK) |
| `V6` L79-92 | `app_deployment` → `dep_application` | dépend de C.4 |
| `V4` | `quality_gate_snapshots.application_id` (colonne UUID, **pas de FK DB**) | stocke `applications.id` = inchangé ✅ |

### C.4 `app_service` vide avant DROP + sort d'`AppDeployment`

- **DROP `app_service`** : sûr **uniquement si la table est vide** (module « brouillon » jamais déployé en prod). ⚠️ **À confirmer manuellement** (`SELECT count(*)`), l'audit statique ne peut pas le prouver. Idem `service_env_var` avant rebranchage FK.
- **`AppDeployment` / `app_deployment`** : le plan est **muet**. Or `ManagedApplication.deployments` (L70) et `AppDeploymentRepository`, `AppDeploymentService`, `AppK8sManifestService`, `ManagedDeploymentWebhookController`, `AppDeploymentResponse` **référencent encore** `AppDeployment` **et** `appmgmt.AppService`. **Point à trancher** (voir verdict).

---

## Bloc D — Intégrité du module de scan (le plus important)

| Fichier | Dépend de… | Dépend du **nom** `Application` ? | Verdict |
|---|---|---|---|
| `QualityGateService` | `gitRepositoryUrl`, `name`, UUID, `SonarProjectKeyUtil.deriveSonarProjectKey(app.getGitRepositoryUrl())` (L1323,1497,4058) | **Non** | ✅ intact |
| `DefectDojoService` | `extractRepoName(app.getGitRepositoryUrl())` (9 appels), `app.getName()`, tag `env-<uuid>` | **Non** | ✅ intact |
| `SonarProjectKeyUtil` | reçoit une `String` (URL) | **Non** (ne connaît pas l'entité) | ✅ intact |
| `ApplicationRepository` | JPQL `FROM Application` | **Oui (nom JPQL)** | ✅ **si `@Entity(name="Application")`** |
| `EphemeralEnvironment` | champ `application` (nom conservé) | Non | ✅ intact |
| `FindingIngestionService` | `env.getApplication().…` | Non | ✅ intact |

### D.1 Appels `getGitRepositoryUrl()` sans garde null

| Fichier | Ligne | Garde null ? | Risque |
|---|---|---|---|
| `DefectDojoService` | 87,181,301,441,524,607,662,713,1976 | Non (via `extractRepoName`) | Nul si `nullable=false` tient |
| `QualityGateService` | 1323,1325,1497,4058 | Partiel (warn si clé Sonar vide) | Nul |
| `EnvironmentService` | 230,255,405 | Non | Nul |
| `SourceSnippetFetcherService` | 79 | Non | Nul |
| `ProjectStackInference` | 33 | `nullToEmpty()` | Déjà robuste |
| `ApplicationService` | 165 | Non | Nul |
| `AdminUserService` | 401 | Non | Nul |
| `AppDeploymentService` | 268 | Non | Nul (couche appmgmt) |

- `gitRepositoryUrl` reste **`nullable=false`** → toute ligne de `applications` (scan-app **et** service fusionné) a une valeur.
- Les services multi-services **ont chacun un repo** → cohérent.
- Si un jour un « service » est créé sans repo, `NOT NULL` échoue **à l'insert** (avant même le scan) → sûr.

**Conclusion Bloc D :** le module de scan ne dépend d'aucun nom de classe — seulement de `gitRepositoryUrl`, `name`, UUID et tag `env-<uuid>`. ✅

---

## Bloc E — Front

| Fichier | Route consommée | Impact |
|---|---|---|
| `services/application/application.service.ts` | `GET/POST api/applications`, `api/applications/{id}`, `.../deployments*` | **Aucun** si routes backend inchangées |
| `services/application-management/application-management.service.ts` | `api/managed-applications` | Aucun (module distinct) |
| Routes Angular | `/my-applications`, `/applications`, `/project/:appId`, `/app-management` | Aucun (IDs = UUID) |

Les noms TS `ApplicationService` / `ApplicationResponse` sont **indépendants** du backend. **Garder `/api/applications` inchangé suffit** — aucun fichier front à toucher. ✅

---

## Fichiers qui CASSERONT à la compilation si non modifiés

Ces fichiers référencent **`entity.appmgmt.AppService` (supprimé)** ou son repository et **ne sont pas couverts** par « rebrancher ServiceEnvVar + AppDatabase » :

| # | Fichier | Cause | Correction requise |
|---|---|---|---|
| 1 | `entity/appmgmt/ManagedApplication.java` | `List<AppService> services` → type supprimé | importer `entity.AppService` + aligner `mappedBy` |
| 2 | `entity/appmgmt/ServiceEnvVar.java` | `AppService appService` | rebrancher vers `entity.AppService` (prévu) |
| 3 | `service/appmgmt/ApplicationManagementService.java` | `new AppService()`, `svc.setApplication()/getApplication()` (L91-92,107,356-357) | rebrancher type **+ renommer accès FK** (`setManagedApplication`) |
| 4 | `service/appmgmt/AppDeploymentService.java` | `List<AppService>`, `AppDeployment` (L6,242,262,286) | rebrancher type / trancher AppDeployment |
| 5 | `service/appmgmt/AppK8sManifestService.java` | `AppService svc`, `ManagedApplication` (L4-5,312,384,627) | rebrancher type |
| 6 | `service/appmgmt/AppDeploymentValidationService.java` | `AppService` (L4,29) | rebrancher type |
| 7 | `repository/AppServiceRepository.java` (appmgmt) | `JpaRepository<AppService,…>` | **supprimer** (prévu) ; ⚠️ ne pas renommer `ApplicationRepository` avant |
| 8 | `controller/appmgmt/AppServiceRequest/Response.java` | import `AppServiceRole` | OK si enum conservé |
| 9 | `controller/appmgmt/ManagedDeploymentWebhookController`, `AppDeploymentResponse`, `ManagedAppResponse`, `AppDeploymentRepository` | `AppDeployment` | trancher (garder/supprimer) |

> **Le plan ne mentionne que le rebranchage des entités (`ServiceEnvVar`, `AppDatabase`). Toute la couche service/controller `appmgmt/` (points 3-6, 9) référence l'ancien type supprimé et NE COMPILERA PAS sans rebranchage explicite.**

---

## Fichiers à risque de `MappingException` au boot

| Fichier | Cause | Prévention |
|---|---|---|
| `ManagedApplication.java` L64 | `mappedBy="application"` sur `List<AppService>` alors que le champ FK dans `AppService` s'appellera `managedApplication` | aligner `mappedBy="managedApplication"` |
| `ManagedApplication.java` L70 | `mappedBy="application"` sur `List<AppDeployment>` si `AppDeployment` conservé mais champ non aligné | aligner ou retirer |
| `ApplicationRepository.java` | 11 JPQL `FROM Application` | **`@Entity(name="Application")`** obligatoire |
| `AppService` (fusionné) | FK `managed_application_id` : le champ JPA doit exister et matcher la colonne migrée | cohérence entité/migration |

---

## Verdict

**La solution n'est PAS applicable telle quelle sans conflit résiduel.**

Le rename symbolique + `@Entity(name="Application")` + champ `application` conservé est **sain pour le module de scan et le front** (Blocs D et E : zéro impact). Mais **3 points bloquants** subsistent :

### Points bloquants à résoudre AVANT application

1. **Couche `appmgmt/` service+controller non rebranchée (BLOQUANT compilation).** Supprimer `appmgmt.AppService` casse `ApplicationManagementService`, `AppDeploymentService`, `AppK8sManifestService`, `AppDeploymentValidationService` (+ leurs appels `svc.getApplication()/setApplication()` de type `ManagedApplication`). Le plan doit **explicitement** : soit rebrancher ces 4-6 fichiers vers `entity.AppService` **et renommer l'accesseur FK** (`getManagedApplication()`), soit **supprimer** cette couche.

2. **`mappedBy` de `ManagedApplication.services` (BLOQUANT boot).** Le champ FK ajouté dans `AppService` vers `ManagedApplication` **doit** porter le nom référencé par `mappedBy` (ex. `managedApplication`), sinon `MappingException`. À figer dans le plan.

3. **Sort d'`AppDeployment` non défini (BLOQUANT compilation/boot).** `ManagedApplication.deployments`, `AppDeploymentRepository/Service`, `AppK8sManifestService`, `ManagedDeploymentWebhookController`, `AppDeploymentResponse` en dépendent. Décider **garder** (aligner) ou **supprimer** (retirer toutes les réfs).

### Prérequis de données (non vérifiable statiquement)

4. Confirmer que **`app_service` et `service_env_var` sont vides** avant `DROP` / rebranchage FK.

### Conditions de succès (si les 4 points ci-dessus sont traités)

- ✅ `@Entity(name="Application")` ajouté (sauve 11 JPQL).
- ✅ Champ `EphemeralEnvironment.application` **nom conservé** (0 impact scan, 0 méthode dérivée à renommer).
- ✅ Nouvelles colonnes **nullable** + Flyway avant Hibernate `update` → pas de perte ni d'erreur de validation.
- ✅ Routes `/api/applications` inchangées → front intact.

**En résumé :** techniquement faisable, mais le plan **sous-spécifie** le rebranchage de toute la couche service/contrôleur `appmgmt/` et le devenir d'`AppDeployment`. Tant que ces éléments ne sont pas ajoutés au plan, l'application laissera **6 à 9 fichiers qui ne compileront pas** et **2 risques de `MappingException`**.

---

*Rapport généré en lecture seule — aucune modification du dépôt.*
