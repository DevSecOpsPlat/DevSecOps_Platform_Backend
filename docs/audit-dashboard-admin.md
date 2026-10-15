# Audit du dashboard admin — état des lieux, bugs confirmés, plan de refonte

Date : 6 septembre 2026. Déclenché par un retour direct de test sur la console admin
(`/admin/*`) : confusion Accueil/Vue d'ensemble, noms d'applications faux dans l'inventaire,
pas de vue de composition au clic, colonne "Statut compte" ambiguë, environnements qui semblent
détachés de leurs applications. Tout ce qui suit a été vérifié dans le code (pas de supposition) :
fichiers frontend lus intégralement, requêtes/DTO backend tracés jusqu'à l'entité JPA et au SQL
généré.

## 0. Modèle de données réel (prérequis pour tout comprendre)

Le point de départ de presque tous les problèmes ci-dessous : la plateforme a **deux notions
distinctes** qui portent toutes les deux le mot « application » dans le langage courant, mais qui
sont représentées par deux entités JPA différentes :

- **`AppService`** (table `app_service`) — l'entité *historique* : un service scannable (repo Git
  + Sonar/DefectDojo), utilisé seul dans le module « Projet » (Chapitres 2/4/5 : quality-gate,
  security-dashboard, scan seul, sans déploiement). Un `AppService` peut être totalement autonome
  (`managedApplicationId = null`) — dans ce cas c'est réellement *l'application entière* pour ce
  projet.
- **`ManagedApplication`** (table `applications`) — l'entité *récente* introduite pour le module
  « Application Management » (Chapitre 3 : multi-services + bases de données managées + un seul
  namespace K8s). Une `ManagedApplication` **contient** plusieurs `AppService` (chacun avec un
  `managedApplicationId` renseigné, un rôle FRONTEND/BACKEND/WORKER, etc.), plus des
  `AppDatabase`, plus des `AppDeployment`.

Autrement dit : `AppService.managedApplicationId == null` → c'est un projet mono-service
autonome (le nom du service EST le nom de l'application). `AppService.managedApplicationId != null`
→ ce service n'est qu'**un composant** d'une application multi-services ; le vrai nom de
l'application est celui de sa `ManagedApplication` parente, pas celui du service.

`AdminMonitoringService` (page Monitoring, déjà en place) connaît et respecte cette distinction :
il résout le nom via `AppDeployment.getApplication().getName()`, donc via `ManagedApplication`. **Ce
n'est PAS le cas de `AdminUserService`**, qui alimente l'Accueil, la Vue d'ensemble, l'Inventaire et
la fiche utilisateur (`toMetricsResponse()`, fichier
`service/admin/AdminUserService.java`) — c'est la source du bug principal ci-dessous.

## 1. Bug confirmé — l'Inventaire (et tout ce qui en dépend) affiche des *services*, pas des
   applications

**Fichier** : `AdminUserService.toMetricsResponse()`, lignes ~406-417.

```java
List<AppService> appList = applicationRepository.findByCreatedByOrderByCreatedAtDesc(u);
List<AdminUserApplicationDetail> appDetails = appList.stream()
        .map(app -> new AdminUserApplicationDetail(
                app.getId(),
                app.getName(),          // <- nom du SERVICE, pas de l'application
                ...
```

`applicationRepository` est en réalité un `AppServiceRepository` (voir l'injection ligne 64 :
`private final AppServiceRepository applicationRepository;` — le nom du champ est trompeur, il
date probablement du renommage `Application → AppService` documenté dans
`audit-rename-application-to-appservice.md`, un renommage purement mécanique qui n'a **jamais**
pris en compte l'arrivée ultérieure de `ManagedApplication`). Le `ManagedApplicationRepository` est
bien injecté dans la classe (ligne 65) mais **n'est utilisé que pour la suppression en cascade**
d'un compte (`deleteUser()`) — jamais pour construire ce qui s'affiche à l'écran.

**Conséquence concrète** : pour un utilisateur qui a une application multi-services (ex. « aoo-1 »
avec les services « back » et « front »), l'admin ne voit **jamais** le nom « aoo-1 » nulle part.
Il voit deux lignes distinctes nommées « back » et « front », comme si c'était deux applications
indépendantes. C'est exactement le « nom des apps il est faux » remonté en test — et ce n'est pas
une coquille de libellé, c'est la mauvaise entité qui est requêtée.

Ce même problème se propage dans trois écrans, parce qu'ils consomment tous
`toMetricsResponse()` / `getAllUsersWithMetrics()` :
- **Inventaire** (`admin-inventory`) — onglet Applications ET onglet Environnements
  (`AdminUserEnvironmentDetail.applicationName` = `e.getService().getName()`, même souci).
- **Vue d'ensemble** (`admin-overview`) — « Applications créées récemment », « Environnements »,
  KPI « Applications ».
- **Fiche utilisateur** (`admin-user-detail`, via `AdminUserMetricsResponse`).

**Pourquoi ça « marchait » quand même pour certains cas** : pour un utilisateur qui n'a que des
projets mono-service autonomes (`managedApplicationId = null`), le nom du service = le nom de
« l'application » du point de vue métier, donc l'affichage est correct par coïncidence. Le bug
n'apparaît que pour les applications multi-services — ce qui explique qu'il soit passé inaperçu
jusqu'à un test avec une vraie app multi-services.

### Pourquoi ça casse aussi "cliquer pour voir la composition"

Comme le modèle exposé est une liste plate de `AppService`, il n'y a structurellement **aucune
notion de composition** à afficher : chaque ligne est déjà un service unique, atomique. Il est
impossible d'ajouter un « clic → voir les services » tant que la source de données n'expose pas le
bon niveau (`ManagedApplication` avec sa collection `services`).

### Pourquoi les environnements « semblent isolés »

Même cause : `AdminUserEnvironmentDetail` ne porte que `applicationName` (= nom du **service**
propriétaire de l'environnement) et son `applicationId` pointe vers l'`AppService`, jamais vers la
`ManagedApplication`. Résultat côté Inventaire : l'onglet Environnements est une liste plate sans
aucun lien de navigation vers l'onglet Applications — même quand l'environnement appartient bel et
bien à une application listée juste à côté. Ce n'est pas qu'un problème d'affichage : le DTO
lui-même ne transporte pas l'identifiant de la `ManagedApplication` parente, donc même un lien
cliquable serait impossible à construire sans changer le backend.

**Référence de bonne pratique déjà présente dans le même projet** : `AdminMonitoringService`
(page Monitoring) résout correctement l'application réelle via
`AppDeployment.getApplication().getName()` et son ID (`ns.appId`), et le frontend
(`admin-monitoring.component.ts`) l'utilise pour appeler `ApplicationManagementService.get(appId)`
et afficher le **vrai** composant `app-monitoring-dashboard` avec la liste des services au clic sur
une ligne d'environnement. C'est exactement le comportement demandé pour l'Inventaire — il existe
déjà, ailleurs dans l'admin, un exemple qui fonctionne et qu'il suffit de réutiliser.

## 2. "Statut compte" dans l'Inventaire — colonne réelle mais mal nommée / mal placée

La colonne `Statut compte` de l'onglet Applications affiche `r.accountStatus`, c'est-à-dire le
statut (ACTIF/DÉSACTIVÉ) du **compte utilisateur propriétaire** de l'application — pas un statut de
l'application elle-même (qui n'existe pas : `ManagedApplication` n'a pas de champ `status`, voir
§0). L'information est légitime (savoir si le propriétaire d'une app encore listée a été désactivé
entre-temps), mais :
- le libellé de colonne, isolé, se lit comme si l'application avait son propre statut ;
- elle est décorrélée visuellement de la colonne « Propriétaire » juste à côté, alors qu'elle en
  est un attribut direct.

**Recommandation** : ne pas en faire une colonne séparée. L'afficher comme un badge secondaire
directement dans la cellule Propriétaire (ex. `nom · email · [Désactivé]` uniquement si désactivé,
rien si actif — cohérent avec le principe *no news is good news* déjà utilisé ailleurs dans la
console). Une colonne entière pour une info qui n'a de sens que dans 5 % des lignes (comptes
désactivés) alourdit le tableau sans raison.

## 3. Accueil vs Vue d'ensemble — doublon confirmé, à trancher

- **`admin-home`** (Accueil) : une page d'accueil quasi statique — un titre de bienvenue et 5
  vignettes qui sont chacune un simple lien vers Vue d'ensemble / Utilisateurs / Inventaire /
  Observabilité / Réclamations, plus un encart texte fixe (« Cadre d'usage »). **Aucune donnée
  chiffrée propre** : les seuls chiffres de la page ("KPI globaux", "vue transverse") sont en fait
  du texte de description statique, pas des valeurs calculées.
- **`admin-overview`** (Vue d'ensemble) : le vrai tableau de bord chiffré — KPI utilisateurs/apps/
  environnements/pipelines, répartition des pipelines, statuts d'environnements agrégés,
  déploiements actifs avec URL, comptes les plus actifs, environnements en anomalie/réussis,
  applications récentes. Toutes ses données viennent de `getAllUsersWithMetrics()`, donc elle
  hérite aussi du bug du §1 (noms d'app affichés = noms de service).

Le contenu de l'Accueil est **entièrement inclus** dans ce que proposent déjà les 5 écrans qu'il
pointe (aucune info n'existe uniquement sur l'Accueil). C'est un pur écran de navigation sans
valeur informationnelle propre. Vue d'ensemble, elle, agrège des données réelles inaccessibles
autrement en un coup d'œil (ex. « déploiements actifs avec URL » tous comptes confondus, ou le
classement des comptes par volume de pipelines) — donc a une vraie raison d'exister,
contrairement à l'Accueil.

**Recommandation** : supprimer l'écran Accueil en tant que tel et faire de **Vue d'ensemble** la
page d'atterrissage de `/admin` (route par défaut). Reprendre uniquement de l'Accueil ce qui a une
valeur propre : le message de bienvenue nominatif et le rappel de cadre d'usage (une phrase, pas
un encart séparé) peuvent devenir un bandeau d'en-tête discret au-dessus des KPI de Vue
d'ensemble. Les 5 vignettes de navigation n'ont plus besoin d'exister comme page à part : elles
existent déjà dans la sidebar. Gain : une entrée de sidebar en moins, un aller-retour en moins pour
l'admin qui se connecte (aujourd'hui : Accueil → clic Vue d'ensemble → vraies données ; demain :
Vue d'ensemble directement).

## 4. Revue écran par écran (les 9 pages)

| Écran | Rôle constaté | Verdict |
|---|---|---|
| Accueil (`admin-home`) | Pure navigation, aucune donnée propre | À supprimer, fusionner dans Vue d'ensemble (§3) |
| Vue d'ensemble (`admin-overview`) | KPI globaux agrégés tous comptes | À garder, devient la page d'accueil ; hérite du bug §1 à corriger |
| Réclamations (`admin-reclamations`) | Messagerie support utilisateur | Périmètre propre, pas de recouvrement identifié |
| Alertes (`admin-alerts`) | SIEM sécurité (menaces, IP bloquées) | Périmètre propre et déjà largement retravaillé cette session |
| Journal d'audit (`admin-audit`) | Traçabilité actions sensibles par compte | Périmètre propre |
| Utilisateurs & activité (`admin-users`) | Gestion des comptes, sécurité par compte | Bien conçu : clic ligne → fiche détail, alertes force brute intégrées. RAS |
| **Apps & environnements (`admin-inventory`)** | **Cible principale de ce document** | **Bug §1 (mauvaise entité), §2 (statut compte), pas de drill-down — refonte nécessaire** |
| Monitoring (`admin-monitoring`) | Cluster K8s temps réel (nœuds, pods, namespaces) | Bon modèle de référence pour la résolution app réelle (§1) et le drill-down au clic |
| Observabilité (`admin-observability`) | Liens SonarCloud + iframe Grafana | Minimal, renvoie déjà explicitement vers Inventaire pour la liste d'apps — cohérent |

Pas d'autre doublon détecté que Accueil/Vue d'ensemble. Utilisateurs, Alertes, Audit,
Réclamations ont chacun un périmètre net et ne se recouvrent pas.

## 5. Ce qui doit changer côté backend (ordre logique)

1. **Nouveau DTO / requête basés sur `ManagedApplicationRepository`**, pas
   `AppServiceRepository`, pour toute vue orientée « application » dans l'admin. Doit exposer, par
   `ManagedApplication` : `id`, `name`, `slug`, `description`, `createdAt`, propriétaire, **la
   liste de ses services** (nom, rôle FRONTEND/BACKEND/WORKER, dépôt Git — même niveau
   d'info que `AppServiceResponse` côté module Application Management), le nombre de bases de
   données, et les environnements qui en découlent (via les déploiements de ses services).
2. **Garder une place pour les `AppService` autonomes** (`managedApplicationId = null`) : ils
   restent de vraies « applications » du point de vue admin (projets mono-service, scan seul). Ne
   pas les faire disparaître de l'inventaire — les traiter comme des lignes « Application » à un
   seul service, sans dupliquer la logique d'affichage (un `ManagedApplication` virtuel à un
   service, ou un flag `standalone: true` sur la même forme de DTO).
3. **Lier explicitement chaque environnement à sa `ManagedApplication` parente** (ou à son
   `AppService` autonome), pas seulement à son `AppService` porteur — pour que l'onglet
   Environnements de l'Inventaire (et Vue d'ensemble) puisse afficher le vrai nom d'application et,
   à terme, un lien de navigation croisé.
4. Réutiliser le pattern déjà éprouvé de `AdminMonitoringService` (résolution via
   `AppDeployment.getApplication()`) plutôt que réinventer une deuxième façon de faire.

## 6. Ce qui doit changer côté frontend — Inventaire (`admin-inventory`)

- **Onglet Applications** : une ligne par `ManagedApplication` (ou projet autonome), pas par
  service. Colonnes : Application (nom réel), Propriétaire (avec badge « Désactivé » inline si
  besoin, cf. §2 — plus de colonne "Statut compte" séparée), Composition (ex. « 2 services · 1
  base de données »), Dépôt(s), Environnements (compteur, cliquable), Pipelines agrégés (succès /
  total, somme de tous les services de l'app).
- **Clic sur une ligne Application → panneau de détail** (expand inline, sur le modèle déjà en
  place dans `admin-monitoring` avec `toggleExpand` / `row-expand-panel`, pas une nouvelle page) :
  liste des services (nom, rôle, dépôt, branche), liste des bases de données, liste des
  environnements de cette application avec leur statut et URL. C'est directement la demande
  formulée : « lorsque je clique sur elle je dois voir sa composition, nb de services ».
- **Onglet Environnements** : ajouter la colonne Application comme lien cliquable qui bascule sur
  l'onglet Applications et ouvre le détail correspondant (au lieu d'un simple texte isolé) — pour
  supprimer l'impression d'environnements détachés de leurs applications.

## 7. Gabarit commun proposé pour une page admin (à appliquer progressivement)

Constat en lisant les 9 écrans : la structure informelle qui s'est dégagée au fil des sprints est
déjà largement cohérente (en-tête avec kicker/titre/lead + bouton Actualiser, état de chargement/
erreur uniforme via `admin-route-page.css`, tableaux `.admin-table` avec le même jeu de classes
cellule). Ce n'est pas à réinventer. Ce qui manque pour en faire un vrai gabarit explicite :

1. **En-tête de page** : `page-kicker` (catégorie sidebar) + `page-title` + `page-lead` (une
   phrase : quelle donnée, quelle source API, quelles limites). Déjà respecté partout sauf
   Accueil (à supprimer, §3).
2. **Bloc KPI optionnel** : uniquement si la page a des compteurs propres à afficher en un coup
   d'œil (Vue d'ensemble, Utilisateurs, Monitoring en ont ; Réclamations, Audit, Observabilité n'en
   ont pas besoin — ne pas en ajouter artificiellement).
3. **Table principale avec drill-down inline** (`row-clickable` + panneau `*ngIf` sous la ligne),
   plutôt qu'une navigation vers une page séparée, chaque fois que le détail reste raisonnablement
   court (déjà le pattern Monitoring ; à adopter pour Inventaire, §6). Réserver la navigation vers
   une page séparée (`admin-user-detail`) aux cas où le détail est lui-même volumineux (fiche
   utilisateur complète).
4. **Filtre de recherche texte simple** en haut de table dès que la liste dépasse ~15-20 lignes
   (déjà présent : Inventaire, Monitoring, Utilisateurs).
5. **Aucun écran ne doit dupliquer des données déjà affichées ailleurs sans valeur ajoutée** — la
   leçon du §3 : un écran doit soit calculer/agréger quelque chose que les autres n'ont pas, soit
   ne pas exister comme page à part entière.

## 8. Plan d'action proposé (ordre d'implémentation)

1. Backend : nouveau DTO application « niveau ManagedApplication » + endpoint(s) dédiés
   (§5), en gardant `AdminUserMetricsResponse` existant pour ce qui n'a pas besoin de changer
   (comptes, pipelines globaux, environnements bruts pour Vue d'ensemble si non refondue tout de
   suite).
2. Frontend : refonte de `admin-inventory` (§6) — c'est l'écran explicitement pointé par le retour
   de test, à traiter en premier.
3. Frontend : `admin-overview` devient la route `/admin` par défaut, suppression de
   `admin-home` et de son entrée de sidebar (§3) — une fois l'Inventaire fiable, pour que les
   widgets de Vue d'ensemble qui listent des applications héritent du bon nom.
4. Ajustement mineur des libellés/colonnes déjà identifiés (§2) au passage de la refonte
   Inventaire, pas séparément.
5. Revalidation manuelle avec un compte de test possédant explicitement une application
   multi-services (ex. « aoo-1 ») ET un projet autonome mono-service, pour couvrir les deux cas du
   §0 dans la même vérification.

Aucune de ces étapes n'a encore été codée à ce stade — ce fichier est l'état des lieux et le plan
à valider avant de commencer l'implémentation.
