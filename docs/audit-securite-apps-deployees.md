# Chantier — Sécurité des applications déployées (par opposition à la sécurité d'EnviroTest elle-même)

Date : 2026-08-31
Périmètre code : `DevSecOps_Platform_Backend`, `DevSecOps_Platform_Frontend`, `EnviroTest/.gitlab-ci.yml`.
Règle : chaque affirmation est sourcée (fichier + méthode/ligne) ; sinon « introuvable dans le code ».

Question de départ (utilisatrice) : *« nous avons sécurisé notre application EnviroTest, mais
est-ce que les applications déployées sont sécurisées aussi ? »* — ce document y répond en
distinguant explicitement les deux périmètres, qui n'avaient jamais été mis côte à côte jusqu'ici :

- **EnviroTest elle-même** (le backend Spring, sa base, son admin) : entièrement couvert par
  `docs/audit-quality-gate.md` et par le chapitre 6 du rapport (authentification JWT + double
  authentification admin, détection d'intrusion, chiffrement des secrets AES-256-GCM, journal
  d'audit).
- **Les applications déployées par les utilisateurs** (le vrai sujet de ce chantier) — deux
  dimensions distinctes existent dans le code, qu'il faut ne pas confondre :
  1. la sécurité **du code** de l'application (ce qu'on scanne : SAST, SCA, secrets, container,
     DAST) ;
  2. la sécurité **de l'exécution** de l'application une fois déployée (isolation réseau, quotas,
     gestion des identifiants) — jamais documentée jusqu'ici, et jamais visible depuis l'interface.

---

## 1. Dimension 1 — Sécurité du code (déjà construite, sprints 2 et 3)

Chaîne complète, déjà en place et déjà documentée ailleurs — rappel volontairement bref (le détail
est dans `docs/audit-quality-gate.md` et les playbooks `src/main/resources/playbooks/*.md`) :

| Outil | Catégorie | Bloquant par défaut ? |
|-------|-----------|------------------------|
| Semgrep | SAST | non (`allow_failure: true`) |
| Trivy (fs), dépendances | SCA | non |
| Gitleaks | Secrets | non au niveau job, **mais** hard gate côté backend (`evaluateHardGates`) |
| Grype | Image container | non |
| Checkov | IaC | non |
| ZAP | DAST (déploiement uniquement, 1 service) | non au niveau job |
| SonarQube | Qualité + SAST | Quality Gate SonarQube = hard gate |

`SecurityScoringService.evaluateHardGates()` bloque le **verdict** (`NON_RECOMMANDE`) dès qu'un
secret est détecté, qu'une vulnérabilité critique est remontée, qu'une anomalie *Blocker* SonarQube
existe, ou que le *Quality Gate* SonarQube échoue. Ce point est important et nuancé plus loin
(section 3) : **bloquer le verdict n'est pas la même chose que bloquer le déploiement.**

## 2. Dimension 2 — Sécurité de l'exécution (jamais documentée, jamais visible)

Chaque environnement déployé vit dans son propre *namespace* Kubernetes
(`AppK8sManifestService`, `K8sManifestApplyService`). Trois mécanismes d'isolation existent, tous
**actifs par défaut** (vérifié en base : `application.properties` + `docker-compose.yml` du
frontend, aucune neutralisation en production) :

### 2.1 Isolation réseau — `NetworkPolicy`

`AppK8sManifestService.networkPolicyManifest()` (L280-303) génère, pour chaque namespace, une
`NetworkPolicy` nommée `default-isolation` :
- sélectionne **tous** les pods du namespace (`podSelector: {}`) ;
- `policyTypes: [Ingress]` — dès qu'un pod est sélectionné, **tout trafic entrant non explicitement
  autorisé est refusé par défaut** (comportement Kubernetes standard) ;
- deux règles d'autorisation seulement : le trafic venant du **même namespace** (les services d'une
  même application communiquent entre eux), et le trafic venant du namespace du contrôleur
  d'ingress (`traefik` en production — `DEPLOYMENT_NETWORK_POLICY_INGRESS_NAMESPACE=traefik`,
  `docker-compose.yml` L44).
- **Effet concret** : un pod d'une application X ne peut pas atteindre un pod d'une application Y
  sur le même cluster, même s'il en connaît l'IP interne — l'isolation est niée au niveau réseau,
  pas juste par méconnaissance du nom du service.
- Activé/désactivé par `deployment.network-policy.enabled` (défaut `true`,
  `application.properties` L181).

### 2.2 Quotas de ressources — `ResourceQuota` + `LimitRange`

`AppK8sManifestService.resourceQuotaManifest()`/`limitRangeManifest()` (L243-264) : chaque
namespace reçoit un `ResourceQuota` (`env-quota`) et un `LimitRange` (`env-limits`) bornant
CPU/mémoire. Empêche qu'une application (buggée ou malveillante) sur le cluster partagé
n'épuise les ressources au détriment des autres locataires (déni de service « bruit de voisinage »).
Activé par `deployment.namespace.resource-quota.enabled` (défaut `true`).
Déjà **partiellement visible** côté utilisateur/admin : `K8sManifestApplyService.getNamespaceMonitoring()`
expose ce quota (`fetchResourceQuotaStatus`, L448-505) dans le monitoring runtime.

### 2.3 Identifiants — jamais en clair dans le pod

- Les variables d'environnement de service marquées `isSecret` passent par un `Secret` Kubernetes
  (`AppK8sManifestService`, commentaire L38-39), et sont elles-mêmes chiffrées au repos côté
  plateforme en AES-256-GCM avant d'atteindre le cluster (même mécanisme que documenté au
  chapitre 3 du rapport).
- Les identifiants de base de données (`dbEnv()`, L439-470) sont systématiquement injectés via
  `secretKeyRef` (`envFromSecret()`, L1058-1063), jamais en variable d'environnement en clair dans
  le manifeste.
- L'accès au registre d'images (`imagePullSecretManifest`) suit le même principe.

### 2.4 Ce qui n'existe PAS (limitations honnêtes, pas de survente)

- **`securityContext` — partiellement comblé le 4 septembre 2026.** Un sous-ensemble sûr
  (`allowPrivilegeEscalation: false`, `capabilities: drop: [ALL]`) est désormais généré pour
  **tous** les conteneurs (services et bases de données) sans exception — casse une image dans de
  très rares cas seulement. `runAsNonRoot` + `readOnlyRootFilesystem` restent en revanche **opt-in**
  par service (`AppService.hardenedSecurityContext`, désactivé par défaut, case à cocher dans le
  formulaire de service) : les imposer partout aurait pu casser des images existantes qui
  s'attendent à tourner en root ou à écrire hors de `/tmp`, sans qu'il soit possible de tester à
  l'avance la compatibilité de chaque application déjà déployée. Quand activé, un volume
  `emptyDir` est monté sur `/tmp` pour absorber les écritures temporaires courantes.
- **Aucune limitation de débit (rate limiting) ni WAF devant le trafic public d'une application
  déployée** : les annotations Traefik générées (`ingressAnnotations()`, L922-942) ne portent que
  sur le routage (`entrypoints`, `passhostheader`, réécriture de chemin) — rien d'équivalent aux
  protections décrites au chapitre 6 pour EnviroTest elle-même (force brute, injection, scan
  automatisé). Une application déployée reste responsable de sa propre exposition HTTP.
- **`deployment.k8s.insecure-skip-tls-verify=true` par défaut** (`application.properties` L163,
  confirmé actif en production — `docker-compose.yml` L35 ne le désactive pas) : le backend ne
  vérifie pas le certificat du serveur d'API Kubernetes auquel il se connecte. N'affecte pas
  directement les applications déployées, mais affaiblit la chaîne de confiance entre le backend et
  le cluster qui les héberge — mentionné ici par souci d'exhaustivité.
- **TLS des URLs publiques des applications déployées** : les annotations Ingress générées ne
  portent aucune configuration TLS/`cert-manager` (`ingressAnnotations()` ne pose que l'entrypoint
  `web`, pas `websecure`) — la terminaison HTTPS observée en pratique
  (`https://<app>.envirotest.cloud`) est donc assurée **au niveau du cluster/Traefik**, hors du
  périmètre du code applicatif ; **introuvable** comme mécanisme explicite dans ce dépôt.

## 3. Le constat le plus important de ce chantier : détection ≠ blocage

C'est la réponse directe, et la plus nuancée, à la question de départ.

- Le pipeline CI **détecte** correctement les vulnérabilités et produit un verdict
  (`RECOMMANDE` / `DEPLOY_WITH_WARNINGS` / `NON_RECOMMANDE`) écrit dans
  `final-report/recommendation.txt` (job `security-validation`).
- Mais la variable qui doit transformer un verdict `NON_RECOMMANDE` en échec réel du pipeline est
  **`DEPLOY_GATE_ENFORCE`, positionnée à `"false"` dans `EnviroTest/.gitlab-ci.yml` (L81)**. Avec
  cette valeur, le bloc `if [ "$DEPLOY_GATE_ENFORCE" = "true" ] && [ "$RECOMMANDATION" = "NON_RECOMMANDE" ]`
  (L2008-2011) ne se déclenche jamais : le job réussit malgré un verdict `NON_RECOMMANDE`.
- Côté backend, `AppDeploymentService` (chemin de déploiement effectif) ne lit **à aucun moment**
  le verdict du *Quality Gate* avant de déployer — recherché explicitement (`NON_RECOMMANDE`,
  `NOT_RECOMMENDED`, verdict), aucune occurrence dans ce fichier.
- **Conséquence concrète, vérifiable en le reproduisant** : aujourd'hui, une application avec une
  vulnérabilité critique détectée et un verdict `NON_RECOMMANDE` peut être déployée sans aucun
  obstacle technique — seul un utilisateur qui lit le verdict avant de cliquer « Déployer » peut
  s'arrêter lui-même. La plateforme informe ; elle n'impose pas (encore).

Ceci n'est **pas** un bug caché : `DEPLOY_GATE_ENFORCE=false` semble être un choix assumé pendant le
développement/la démonstration (éviter qu'un faux positif ou un outil temporairement indisponible ne
bloque toute la plateforme). Mais ce n'était documenté nulle part comme une décision, et rien dans
l'interface n'indique à l'utilisateur que le verdict n'est actuellement qu'indicatif. Deux options,
non implémentées ici (changement de comportement en production, à valider avant tout code) :
1. passer `DEPLOY_GATE_ENFORCE=true` (blocage réel, au risque de bloquer des démos si un outil
   d'analyse est temporairement indisponible) ;
2. ajouter un blocage **côté backend** (indépendant de la variable CI), avec une option explicite
   « déployer quand même » réservée à l'utilisateur — plus visible, plus honnête, mais plus de
   travail.

## 4. Ce qui a été ajouté par ce chantier

Le seul écart trouvé entre « information disponible dans le cluster » et « information visible
dans l'interface » concernait l'isolation réseau (le quota, lui, était déjà exposé — section 2.2) :

- **Backend** — `K8sManifestApplyService.fetchNetworkPolicyStatus(namespace)` (nouveau) : relit la
  `NetworkPolicy` `default-isolation` réellement présente sur le namespace (et pas seulement le fait
  qu'elle ait été envoyée au déploiement), exposée dans `getNamespaceMonitoring()` sous la clé
  `networkPolicy`. Bénéficie automatiquement à `AdminMonitoringService.getNamespaceDetail()`
  (admin) et au monitoring applicatif utilisateur, qui partagent la même méthode.
- **Frontend** — `monitoring-dashboard.component.ts/.html` : nouvelle carte « Isolation réseau »
  (badge Active/Absente + nombre de règles d'entrée autorisées), à côté de la carte Quota
  existante. Visible depuis la console admin (`admin-monitoring.component.html`) et depuis le
  monitoring applicatif utilisateur (`application-detail`, `project/monitoring`).
- **Modèle** — `NetworkPolicyInfo` ajouté à `application-management.models.ts`.

Aucun changement de comportement de déploiement (le point de la section 3 n'a pas été touché — décision
produit à valider avant tout code, comme convenu pour tout changement de ce type).

## 5. Preuves — commandes à exécuter

### 5.1 EnviroTest elle-même (déjà couvert par le chapitre 6, rappelé ici pour mémoire)

```bash
# JWT obligatoire — doit renvoyer 401/403 sans jeton
curl -i https://<host-envirotest>/api/managed-applications

# Détection d'intrusion — chemin-piège, doit être bloqué (403/404 selon config) et journalisé
curl -i https://<host-envirotest>/.env
curl -i "https://<host-envirotest>/api/search?q=1%20UNION%20SELECT%20NULL--"

# HTTPS imposé / HSTS présent
curl -sI https://<host-envirotest>/ | grep -i strict-transport-security
```

### 5.2 Applications déployées — isolation réseau (preuve directe, à faire depuis un pod)

```bash
# Lister les namespaces d'environnements actifs
kubectl get ns | grep ^env-

# Vérifier que la NetworkPolicy existe bien sur un namespace donné
kubectl get networkpolicy -n <namespace> default-isolation -o yaml

# Preuve la plus parlante : depuis un pod de l'app A, tenter de joindre un pod de l'app B
# (remplacer <pod-A> / <namespace-A> / <ip-pod-B> par des valeurs réelles du cluster)
kubectl exec -n <namespace-A> <pod-A> -- curl -m 3 -s -o /dev/null -w "%{http_code}\n" http://<ip-pod-B>:<port>
# Résultat attendu : timeout / connexion refusée (isolation active) plutôt qu'un code HTTP.
```

### 5.3 Applications déployées — quotas de ressources

```bash
kubectl describe resourcequota env-quota -n <namespace>
kubectl describe limitrange env-limits -n <namespace>
```

### 5.4 Applications déployées — identifiants jamais en clair

```bash
# La valeur doit être absente du Deployment (seule la référence au Secret doit apparaître)
kubectl get deployment -n <namespace> -o yaml | grep -A2 secretKeyRef

# Le secret existe bien, séparé du manifeste applicatif
kubectl get secret -n <namespace>
```

### 5.5 Applications déployées — verdict de sécurité vs déploiement réel (le constat de la section 3)

```bash
# 1. Provoquer un scan qui obtient NON_RECOMMANDE (ex. app avec une vulnérabilité critique connue)
# 2. Lire le verdict retourné par la plateforme
curl -s https://<host-envirotest>/api/quality-gate/... | jq '.verdict'
# 3. Déployer quand même la même application depuis l'interface — aujourd'hui, rien ne l'empêche.
```

---

*Document créé le 31 août 2026 dans le cadre du chantier « sécurité des applications déployées »,
distinct de `audit-quality-gate.md` (qui couvre le calcul du score, pas l'exécution runtime).*
