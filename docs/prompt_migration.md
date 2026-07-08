l'audit  ce que tu dois faire enrichir Application existante (PAS de ManagedApplication)


Ce prompt REMPLACE l'approche « ManagedApplication / AppDeployment ». On unifie sur le modèle existant.
Référence : 01-cadrage-architecture.md — mais ignore les entités ManagedApplication et AppDeployment : elles sont abandonnées.




Décision d'architecture (à respecter strictement)

On NE crée PAS de nouvelles entités « application » ou « déploiement ». On réutilise l'existant :


L'entité Application existante devient le conteneur de services + bases (en plus de son ancien repo unique, gardé en legacy).
L'entité EphemeralEnvironment existante RESTE l'unité de déploiement + scan. On ne la duplique pas avec un « AppDeployment ». Chaque EphemeralEnvironment est un déploiement d'une Application (c'est déjà le cas).
Si des entités ManagedApplication / AppDeployment ont été créées, SUPPRIME-les ainsi que leurs repositories/services/DTO associés.


Règle de non-régression

Le module de scan (quality-gate, DefectDojo, SonarQube, pipeline actuel, filtrage des vulnérabilités par EphemeralEnvironment) doit continuer de fonctionner à l'identique. Tu procèdes par ajout de champs/relations, jamais par suppression de champs existants.

Changements backend

1. Entité Application (fichier existant entity/Application.java) — modification ADDITIVE


Rendre gitRepositoryUrl nullable : @Column(name = "git_repository_url", length = 500) (retirer nullable = false). Raison : une app multi-services n'a pas de repo unique. Les anciennes apps gardent leur valeur.
Garder encryptedGithubToken, dockerfilePath tels quels (legacy, optionnels).
AJOUTER deux relations :


java@OneToMany(mappedBy = "application", cascade = CascadeType.ALL, orphanRemoval = true)
private List<AppService> services = new ArrayList<>();

@OneToMany(mappedBy = "application", cascade = CascadeType.ALL, orphanRemoval = true)
private List<AppDatabase> databases = new ArrayList<>();


Ne touche PAS à ephemeralEnvironments, createdBy, ni aux méthodes existantes.


2. Nouvelles entités (dans entity/appmgmt/)

Crée AppService, AppDatabase, ServiceEnvVar selon §2.2/§2.3/§2.4 de 01-cadrage-architecture.md, MAIS :


Le champ application_id pointe vers l'entité Application existante (com.backend.devsecopsplatform_backend.entity.Application), pas vers ManagedApplication.
AppService.depends_on_service_id → FK vers AppService (auto-référence, nullable).
AppService.depends_on_database_id → FK vers AppDatabase (nullable).
Chiffrement au repos (AttributeConverter AES) pour AppService.git_token, AppDatabase.root_password, ServiceEnvVar.var_value si is_secret. Réutilise le mécanisme de chiffrement DÉJÀ utilisé pour Application.encryptedGithubToken (même convertisseur/clé) — ne crée pas un second système de chiffrement.


3. Déploiement = EphemeralEnvironment (réutilisation)


N'ajoute PAS d'entité de déploiement. Quand l'utilisateur déploie une application multi-services, tu crées un EphemeralEnvironment comme aujourd'hui (il a déjà application, namespace, status, url, pipelineExecution).
Si EphemeralEnvironment a besoin de mémoriser l'état par service (Ready/NotReady, URL interne de chaque service), AJOUTE un champ JSONB services_state (nullable) — sans retirer l'existant.


4. Repositories / Services / Controller


AppServiceRepository, AppDatabaseRepository, ServiceEnvVarRepository.
Nouveau ApplicationCompositionController (ou étends proprement le contrôleur d'applications existant SANS casser ses routes) sous /api/applications/{id}/services, /databases, /env-vars — endpoints du §4 du cadrage, en retirant tout ce qui référençait ManagedApplication/AppDeployment.
Validation pré-déploiement (§3.2) : backend sans BD liée, deps inter-app.
Génération de l'URL de connexion BD (§3.1) + injection dans les services dépendants.


5. Migration base de données


git_repository_url : passer la contrainte NOT NULL à NULL (migration ALTER).
Créer les tables app_service, app_database, service_env_var avec FK vers applications(id).
Ajouter services_state JSONB à ephemeral_environments si nécessaire.
Compatible avec la stratégie de migration existante (Flyway/Liquibase/ddl-auto).


Changements frontend


Réutilise le concept d'application existant. Ajoute les composants service-form, database-form, et enrichis la page de détail d'application avec les sections Services / Bases (§5 du cadrage).
Le suivi de déploiement s'appuie sur l'EphemeralEnvironment/pipeline existant, pas sur un nouveau « deployment ».
Ne modifie PAS les pages de scan / quality-gate existantes.


Ce que tu NE fais PAS


Pas de ManagedApplication, pas de AppDeployment (supprime-les si présents).
Pas de second système de chiffrement.
Pas de modification des routes/pages de scan existantes.
Pas de suppression de champs existants sur Application ou EphemeralEnvironment.


Livrables


Montre d'abord le diff de Application.java (les 3 changements : nullable + 2 relations) et les 3 nouvelles entités, pour validation.
Confirme que ManagedApplication/AppDeployment sont supprimés s'ils existaient.
Puis génère repositories, controller, migrations, front.