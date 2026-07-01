# EnviroTest — Cadrage : séparation Déploiement / Scan + gestion Applications & Services

## 0. Décisions actées (ne pas rediscuter)

| Sujet | Décision |
|---|---|
| Séparation | Déploiement et Scan deviennent deux flux distincts. On garde l'ancien pipeline mais on en extrait **clone → build → deploy** dans un pipeline dédié « déploiement ». Le scan reste un pipeline séparé, déclenchable après. |
| Orchestrateur | Kubernetes local (un **namespace par application**). |
| Registry | **GitLab Container Registry** (`$CI_REGISTRY_IMAGE`), privé, auth automatique dans le pipeline. |
| BD | Ressource managée (pas un service applicatif). Image officielle + volume persistant + Secret. |
| URL BD | **Générée automatiquement** par la plateforme, injectée dans le backend via **Secret K8s**, puis **affichée en lecture seule** dans l'UI après déploiement (mot de passe masqué). L'utilisateur ne la saisit jamais. |
| Dépendances | Déclaratives et simples : un service peut déclarer « dépend de » une BD et/ou un service backend. Vide = démarre tout de suite. Pas de graphe arbitraire. |
| Règle backend/BD | Si un service de rôle **backend** déclare consommer une BD mais qu'aucune BD n'existe dans l'app → **erreur de validation** au déploiement. |
| Secrets | Password BD stocké **chiffré** en base, jamais en clair. Masqué par défaut dans l'UI. |

---

## 1. Concept — comment les vraies plateformes font (Vercel / Render / Railway / Qovery)

Le modèle universel est **Application → (Services + Ressources) → Environnement déployé**.

- **Application** = conteneur logique = un **namespace K8s**. Regroupe tout ce qui appartient à un projet.
- **Service** = une unité applicative déployable depuis un repo Git (front, back, worker). A : source (repo + token), build (Dockerfile), variables d'env, rôle, dépendances.
- **Ressource managée** = une brique d'infra provisionnée par la plateforme, PAS buildée depuis un repo (BD SQL/NoSQL, cache…). Utilise une image officielle, un volume persistant, des credentials générés.
- **Environnement** = l'instance qui tourne réellement dans le cluster après déploiement.

Ordre de démarrage (déduit, pas dessiné à la main) :
1. Les **ressources** (BD) démarrent en premier et exposent un DNS interne stable.
2. Les **services qui déclarent dépendre** d'une ressource/service attendent que la dépendance soit *Ready* (readiness probe).
3. Les **services sans dépendance** (ex. front seul) démarrent immédiatement.

Ça couvre les 3 cas réels :
- Tester **le front seul** → aucune BD, aucun backend.
- Tester **backend + BD** → BD d'abord, backend attend.
- Tester **tout** → BD → backend → front.

---

## 2. Modèle de données (backend)

> Convention : tout est rattaché à un `User` (créateur) comme le reste de l'app. UUID en PK. `created_at` / `updated_at` partout.

### 2.1 `application`
Le conteneur logique = namespace.

| Champ | Type | Notes |
|---|---|---|
| id | UUID | PK |
| name | String | Nom lisible |
| slug | String | Dérivé du nom, unique, sert au nom de namespace (`env-<slug>-<envId>`) |
| description | String? | Optionnel |
| created_by | FK User | Propriétaire |
| created_at / updated_at | Instant | |

> ⚠️ Ne PAS réutiliser l'entité `Application` existante si elle est déjà couplée au repo unique + scan. Créer une nouvelle notion **ou** étendre proprement. Voir §6 (migration).

### 2.2 `app_service`
Un service applicatif (front / back / worker).

| Champ | Type | Notes |
|---|---|---|
| id | UUID | PK |
| application_id | FK application | |
| name | String | Ex. « frontend », « api » |
| role | Enum `FRONTEND \| BACKEND \| WORKER` | Détermine la logique de dépendance et l'exposition |
| git_repository_url | String | URL du repo |
| git_token | String (chiffré) | Token GitHub, **chiffré au repos** |
| git_branch | String | Défaut `main` |
| dockerfile_path | String | Défaut `Dockerfile` (chemin dans le repo) |
| build_context | String | Défaut `.` |
| exposed_port | Integer | Port que le conteneur écoute (ex. 8080, 4200, 3000) |
| depends_on_service_id | FK app_service? | Optionnel — dépend d'un autre service |
| depends_on_database_id | FK app_database? | Optionnel — consomme une BD |
| db_url_env_var | String? | Nom de la variable où injecter l'URL BD (défaut `DATABASE_URL`) — utile seulement si `depends_on_database_id` non nul |
| replicas | Integer | Défaut 1 |
| health_check_path | String? | Ex. `/health` — pour readiness probe (optionnel) |
| created_at / updated_at | Instant | |

### 2.3 `app_database`
Une ressource BD managée.

| Champ | Type | Notes |
|---|---|---|
| id | UUID | PK |
| application_id | FK application | |
| name | String | Ex. « main-db » |
| db_family | Enum `SQL \| NOSQL` | |
| engine | Enum | Si SQL : `MARIADB \| POSTGRES \| MYSQL`. Si NOSQL : `MONGODB \| REDIS \| CASSANDRA` |
| version | String | Ex. « 10.11 », « 16 » — sert au tag de l'image officielle |
| db_name | String | Nom de la base à créer |
| root_user | String | Ex. `root` / `admin` |
| root_password | String (chiffré) | **Chiffré au repos**, masqué dans l'UI |
| exposed_port | Integer | Auto selon engine (MariaDB 3306, Postgres 5432, Mongo 27017, Redis 6379) — pré-rempli, modifiable |
| storage_size | String | Ex. « 1Gi » — taille du PVC |
| generated_connection_url | String? | **Rempli par la plateforme après déploiement**, lecture seule côté UI |
| created_at / updated_at | Instant | |

### 2.4 `service_env_var`
Variables d'environnement (optionnelles) d'un service. Table séparée = facile à éditer en BD (ton besoin explicite).

| Champ | Type | Notes |
|---|---|---|
| id | UUID | PK |
| app_service_id | FK app_service | |
| var_key | String | Ex. `NODE_ENV` |
| var_value | String (chiffré si `is_secret`) | |
| is_secret | Boolean | Si true → va dans un Secret K8s, chiffré en base, masqué UI |
| created_at / updated_at | Instant | |

### 2.5 `deployment` (remplace/complète l'ancienne notion d'environnement de déploiement)
Une exécution de déploiement d'une application (produit le namespace + les workloads).

| Champ | Type | Notes |
|---|---|---|
| id | UUID | PK |
| application_id | FK application | |
| namespace | String | `env-<slug>-<shortid>` |
| status | Enum `PENDING \| DEPLOYING \| RUNNING \| FAILED \| STOPPED` | |
| gitlab_pipeline_id | Long? | Pipeline de déploiement |
| deployed_at | Instant? | |
| services_state | JSONB | État par service (Ready / NotReady / URL interne) |
| created_at / updated_at | Instant | |

> Le **scan** (pipeline existant) se rattache à ce `deployment` : on scanne un environnement qui tourne. C'est le lien entre les deux flux séparés.

---

## 3. Logique métier clé (à implémenter côté backend)

### 3.1 Génération de l'URL BD (le cœur)
Quand une BD est déployée dans le namespace :
- Nom du Service K8s : `db-<database.name>` → DNS interne : `db-<name>.<namespace>.svc.cluster.local`.
- Construire l'URL selon `engine` :
  - MariaDB/MySQL : `jdbc:mariadb://db-<name>.<namespace>:3306/<db_name>` (+ user/password séparés ou dans l'URL selon la convention du backend)
  - Postgres : `jdbc:postgresql://db-<name>.<namespace>:5432/<db_name>`
  - MongoDB : `mongodb://<root_user>:<root_password>@db-<name>.<namespace>:27017/<db_name>`
  - Redis : `redis://db-<name>.<namespace>:6379`
- Stocker dans `app_database.generated_connection_url`.
- Pour chaque service ayant `depends_on_database_id = cette BD` : injecter l'URL sous le nom `db_url_env_var` (défaut `DATABASE_URL`) **via un Secret K8s**, pas en clair dans le Deployment.

### 3.2 Validation avant déploiement (empêche les incohérences)
Refuser (400 + message clair) si :
- Un service `BACKEND` a `depends_on_database_id` non nul mais la BD n'existe pas / pas dans la même application.
- Un service `BACKEND` déclare consommer une BD mais aucune BD n'est définie dans l'app → message : « Un backend nécessite une base de données. Ajoutez d'abord une base ou retirez la dépendance. »
- Un service référence `depends_on_service_id` d'une autre application.
- Deux services exposent le même `exposed_port` sur le même hostname (collision d'ingress) — avertissement, pas blocage.

### 3.3 Ordre de déploiement (topological, mais borné)
1. Déployer toutes les `app_database` → attendre Ready.
2. Déployer les services **avec** `depends_on_*` → attendre que leurs deps soient Ready.
3. Déployer les services **sans** dépendance en parallèle.
Comme la profondeur est bornée (service → backend → BD au max), un simple tri en 3 vagues suffit. Pas besoin d'algo de graphe générique.

### 3.4 Chiffrement des secrets
- `git_token`, `root_password`, `var_value` (si `is_secret`) : chiffrés en base (ex. AES via une clé dans la config backend, `@Convert` JPA AttributeConverter).
- Jamais renvoyés en clair par l'API : masqués (`••••••`) avec un endpoint séparé « révéler » si vraiment nécessaire.

---

## 4. Endpoints backend (nouveau contrôleur, ne touche pas l'existant)

`@RequestMapping("/api/applications")` — nouveau `ApplicationManagementController`.

| Méthode | Route | Rôle |
|---|---|---|
| POST | `/` | Créer une application |
| GET | `/` | Lister les applications du user |
| GET | `/{id}` | Détail (services + bases + env vars, secrets masqués) |
| PUT | `/{id}` | Modifier nom/description |
| DELETE | `/{id}` | Supprimer (cascade services/bases) |
| POST | `/{id}/services` | Ajouter un service |
| PUT | `/{id}/services/{sid}` | Modifier un service |
| DELETE | `/{id}/services/{sid}` | Supprimer un service |
| POST | `/{id}/databases` | Ajouter une base |
| PUT | `/{id}/databases/{dbid}` | Modifier une base |
| DELETE | `/{id}/databases/{dbid}` | Supprimer une base |
| GET/POST/PUT/DELETE | `/{id}/services/{sid}/env-vars` | CRUD variables d'env |
| POST | `/{id}/deploy` | Lancer le déploiement (déclenche le pipeline de déploiement) |
| GET | `/{id}/deployments` | Historique des déploiements |
| GET | `/{id}/deployments/{did}` | État d'un déploiement (statuts par service + URLs internes générées) |
| POST | `/{id}/deployments/{did}/reveal-secret` | Révéler un secret précis (audit log conseillé) |

---

## 5. Interfaces front (nouveaux composants, on NE TOUCHE PAS les pages existantes)

Tous en composants Angular standalone, charte orange `#F97316` / navy `#1C1C2E` (cohérence avec le reste).

1. **`applications-list.component`** — liste des applications (cartes), bouton « Créer une application ».
2. **`application-create.component`** — formulaire simple (nom, description).
3. **`application-detail.component`** — vue d'une application : onglets/sections **Services** et **Bases de données**, boutons « Ajouter un service » / « Ajouter une base », bouton « Déployer », état du dernier déploiement.
4. **`service-form.component`** — formulaire d'ajout/édition de service :
   - name, role (select FRONTEND/BACKEND/WORKER)
   - git_repository_url, git_token (champ password)
   - git_branch, dockerfile_path, build_context, exposed_port
   - **« Base de données liée »** (select des BD de l'app + « aucune ») → si choisi, affiche **« Nom variable d'injection »** (défaut `DATABASE_URL`)
   - **« Dépend du service »** (select des services de l'app + « aucun »)
   - replicas, health_check_path (optionnel)
   - **Variables d'environnement** (liste dynamique key/value + case « secret ») — **optionnel**
5. **`database-form.component`** — formulaire d'ajout/édition de base :
   - name
   - db_family (select SQL / NoSQL)
   - engine (select dépendant : SQL→MariaDB/Postgres/MySQL ; NoSQL→MongoDB/Redis/Cassandra)
   - version, db_name, root_user, root_password (champ password), storage_size
   - exposed_port pré-rempli selon engine
6. **`deployment-status.component`** — état du déploiement en cours/terminé : liste des services avec statut (Ready/NotReady), et pour la BD **l'URL de connexion générée affichée en lecture seule** (password masqué + bouton révéler).

Comportements UI importants :
- Le select `engine` se met à jour dynamiquement selon `db_family`.
- Si l'utilisateur ajoute un backend avec « Base de données liée » = aucune, afficher un **avertissement inline** : « Un backend a généralement besoin d'une base. Continuer sans ? »
- Le formulaire n'accepte PAS d'upload de fichier `.env` (ton choix) : uniquement des champs éditables → facile à modifier en base.

---

## 6. Migration / non-régression (IMPORTANT pour Cursor)

- **Ne modifie AUCUNE page ni composant existant** (quality-gate, pipeline actuel, dashboards). On ajoute, on ne remplace pas.
- Nouvelles entités, nouveau contrôleur, nouveaux composants, nouvelles routes front.
- L'ancien pipeline « tout-en-un » reste fonctionnel tant que le nouveau flux n'est pas validé.
- Le pipeline de **déploiement** (fourni séparément) est un nouveau fichier `.gitlab-ci` (ou template) — l'utilisateur (toi) le place dans le projet, Cursor ne l'écrit pas.
- Prévoir les migrations Flyway/Liquibase (ou `ddl-auto=update` si c'est ce que tu utilises déjà) pour les nouvelles tables.

---

## 7. Ce que tu avais oublié (je l'ajoute)

1. **Exposition externe des services** : un front déployé doit être accessible. Prévoir un **Ingress** (ou NodePort) par service exposé, avec une URL type `http://<service>-<namespace>.local`. Sinon l'utilisateur déploie mais ne peut rien voir.
2. **Readiness / liveness probes** : sans elles, le backend démarre avant que la BD soit prête et crashe. `health_check_path` sert à ça.
3. **Nettoyage (teardown)** : pouvoir **supprimer un déploiement** = supprimer le namespace K8s (sinon le cluster local sature). Endpoint `DELETE /deployments/{id}` + suppression namespace.
4. **Nom de variable d'injection BD configurable** (déjà intégré : `db_url_env_var`) — sinon ça ne marche que pour une seule techno.
5. **Chiffrement des tokens/passwords** (déjà intégré §3.4) — critique pour le contexte gouvernemental INSAF, le jury le regardera.
6. **ImagePullSecret** : le cluster doit pouvoir puller depuis GitLab Registry privé → créer un `imagePullSecret` dans chaque namespace au déploiement.
7. **Idempotence du déploiement** : redéployer la même app ne doit pas dupliquer les workloads (apply, pas create).
8. **Limites de ressources** (requests/limits CPU/mémoire) par service — sinon un test peut saturer ta machine locale. Champs optionnels avec défauts raisonnables.