## Playbook: Dépendance vulnérable (SCA — tous écosystèmes)

### Quand ça arrive
- ScanType SCA (Trivy fs, npm audit, pip-audit, OSV…) : une dépendance du projet a un CVE connu.
- Le finding donne en général : `packageName`, `installedVersion`, `fixedVersion`, un CVE.

### Principe universel (identique quel que soit le langage)
1) **Identifier** la dépendance et si elle est **directe** (déclarée dans le manifest) ou **transitive** (tirée par une autre).
2) **Mettre à jour** vers `fixedVersion` (ou la version corrigée la plus proche).
3) Si **transitive** : mettre à jour le parent, ou forcer la résolution avec le mécanisme d'override de l'écosystème.
4) **Committer le manifest ET le lockfile**, vérifier build + tests, push, puis relancer l'analyse depuis la plateforme.
5) Si **aucune version corrigée** n'existe : évaluer si le code vulnérable est réellement appelé, chercher une alternative, ou documenter l'acceptation du risque.

### IMPORTANT — le finding porte sur un PACKAGE, pas un fichier source
Le « fichier » indiqué est souvent le lockfile (`package-lock.json`, `poetry.lock`…) ou un rapport JSON produit par le CI (`reports/...`) : ce n'est pas du code à corriger ligne par ligne.

### Adaptation par écosystème — utiliser PIPELINE_CONTEXT pour choisir la bonne section

**Node.js (npm / yarn / pnpm)** — manifest `package.json`, lockfile `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml`
```bash
npm ls <package>                       # provenance directe/transitive
npm install <package>@<fixedVersion>   # dépendance directe
npm audit --audit-level=high
```
Transitive : bloc `"overrides"` (npm ≥ 8) ou `"resolutions"` (yarn) dans `package.json`. Éviter `npm audit fix --force` sans revue (mises à jour majeures).

**Java (Maven / Gradle)** — manifest `pom.xml` / `build.gradle`
```bash
mvn dependency:tree -Dincludes=<groupId>:<artifactId>   # provenance
mvn versions:display-dependency-updates
mvn test
```
Directe : changer `<version>` dans `pom.xml`. Transitive : contrainte dans `<dependencyManagement>` ; Gradle : bloc `constraints` ou `resolutionStrategy.force`. Spring Boot : privilégier la montée de version du BOM Boot plutôt que forcer une lib isolée.

**Python (pip / Poetry / pipenv)** — `requirements.txt` / `pyproject.toml`
```bash
python -m pip show <package>
pip-audit
```
Directe : épingler `package==<fixedVersion>` puis `pip install -r requirements.txt` ; Poetry : `poetry update <package>`. Transitive : contrainte via `constraints.txt` (`pip install -c constraints.txt`) ou mise à jour du parent.

**.NET / C# (NuGet)** — `.csproj` / `packages.lock.json`
```bash
dotnet list package --vulnerable --include-transitive
dotnet add package <Package> --version <fixedVersion>
dotnet build && dotnet test
```
Transitive : ajouter une `<PackageReference>` directe à la version corrigée (elle prime), ou Central Package Management (`Directory.Packages.props`).

**Go (modules)** — `go.mod` / `go.sum`
```bash
go list -m all | grep <module>
go get <module>@<fixedVersion> && go mod tidy
govulncheck ./...
```

**Rust (Cargo)** — `Cargo.toml` / `Cargo.lock`
```bash
cargo tree -i <crate>
cargo update -p <crate> --precise <fixedVersion>
```

**PHP (Composer)** — `composer.json` / `composer.lock`
```bash
composer why <package>
composer update <package> --with-dependencies
composer audit
```

**C / C++** — pas de gestionnaire standard : si vcpkg/Conan présents, mettre à jour la recette (`vcpkg.json` / `conanfile`) ; sinon la « dépendance » est souvent une lib système de l'image Docker → appliquer le playbook Container/Grype (mise à jour image de base ou paquet OS).

### Vérification (générique)
- Re-exécuter l'outil d'audit de l'écosystème (ci-dessus) : le CVE ne doit plus apparaître.
- Build + tests verts, lockfile commité, puis relancer l'analyse depuis la plateforme.

### Notes
- Un saut de version **majeure** peut casser l'API : lire le changelog avant de monter de plusieurs versions.
- Toujours committer le lockfile mis à jour, sinon le scan suivant retrouvera l'ancienne version.
