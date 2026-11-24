## Playbook : Trivy (dépendances vulnérables)

### Quand ça arrive
- `trivy fs --scanners vuln` sur le dépôt cloné : une **dépendance** du projet a une vulnérabilité connue (CVE).
- Le finding donne en général : le paquet, `installedVersion`, `fixedVersion`, le CVE.
- Dans EnviroTest, Trivy ne traite que les dépendances : secrets → Gitleaks, configuration → Checkov / Hadolint.

### Important : le finding porte sur un paquet, pas sur du code
Le fichier indiqué est le manifeste ou le lockfile (`package-lock.json`, `pom.xml`, `poetry.lock`…).
Ne pas proposer de modifier le code source : la correction est une montée de version.

### Démarche
1. Identifier le paquet, son écosystème (chemin du lockfile, PIPELINE_CONTEXT) et s'il est **direct** ou **transitif**.
2. Monter vers `fixedVersion` (ou la version corrigée la plus proche, sans saut majeur inutile).
3. Transitif : mettre à jour le parent, sinon forcer la version (ci-dessous).
4. Committer le manifeste **et** le lockfile, build + tests, puis relancer l'analyse depuis la plateforme.

### Par écosystème
- **Node.js** : `npm ls <pkg>` (provenance) ; `npm install <pkg>@<fixedVersion>` ; transitif → `"overrides"` (npm ≥ 8) ou `"resolutions"` (yarn). Éviter `npm audit fix --force` sans revue.
- **Java** : `mvn dependency:tree -Dincludes=<groupId>:<artifactId>` ; direct → `<version>` dans `pom.xml` ; transitif → `<dependencyManagement>` ; Gradle → `constraints`. Spring Boot : préférer la montée du BOM.
- **Python** : `pipdeptree` (provenance) ; épingler dans `requirements.txt` ou `poetry add <pkg>@<v>` ; transitif → fichier de contraintes.
- **.NET** : `dotnet add package <Pkg> --version <fixedVersion>`.
- **Go** : `go get <module>@<version>` puis `go mod tidy`.
- **Rust / PHP** : `cargo update -p <crate> --precise <v>` ; `composer require <pkg>:<v>`.

### Vérification locale
```bash
trivy fs --scanners vuln --severity CRITICAL,HIGH,MEDIUM .
```
Le CVE ne doit plus apparaître ; build et tests au vert.

### Notes
- Un paquet peut porter plusieurs CVE : traiter **par paquet**, une montée de version en corrige souvent plusieurs.
- `fixedVersion` vide : aucune version corrigée publiée → vérifier si le code vulnérable est réellement utilisé, chercher une alternative ou documenter l'acceptation du risque.
- Saut de version majeure : lire le changelog, l'API peut changer.
