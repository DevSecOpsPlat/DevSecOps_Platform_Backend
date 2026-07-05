## Playbook: Trivy FS (scan du dépôt — vuln / misconfig / secret / licence)

### Quand ça arrive
- Outil : `trivy fs` sur le dépôt cloné. Trivy est **multi-détecteurs** : le même scan produit 4 natures de findings très différentes. La première étape est TOUJOURS de qualifier la nature.

### Étape 0 — Qualifier la nature du finding
| Indice dans le finding | Nature | Démarche |
|---|---|---|
| CVE + packageName + installedVersion/fixedVersion | **Dépendance vulnérable** | Suivre la démarche SCA multi-écosystèmes (identifier direct/transitif → monter à fixedVersion → committer manifest + lockfile) |
| ID `AVD-...` / KSV / fichier .tf, .yaml, Dockerfile | **Misconfiguration IaC** | Même logique que Checkov : moindre privilège, chiffrement, pas d'exposition publique |
| « secret », clé, token, AWS/GitHub key | **Secret en dur** | Suivre le playbook Secrets : révoquer d'abord, externaliser ensuite |
| Licence (GPL, unknown…) | **Conformité licence** | Impact légal, pas d'attaquant — vérifier la licence réelle et la politique |

### Cas 1 — Dépendance vulnérable (le plus fréquent avec trivy fs)
Trivy lit les **lockfiles** (`package-lock.json`, `pom.xml`, `poetry.lock`, `go.mod`, `Cargo.lock`, `composer.lock`…). La remédiation dépend de l'écosystème indiqué par le chemin du lockfile et par PIPELINE_CONTEXT :
- Node : `npm install <pkg>@<fixedVersion>` (+ `overrides` si transitif)
- Java : version dans `pom.xml` / `dependencyManagement` (BOM Spring Boot de préférence)
- Python : épingler dans `requirements.txt` / `poetry update <pkg>`
- .NET : `dotnet add package <Pkg> --version <fixedVersion>` ; Go : `go get <mod>@<v> && go mod tidy`
Toujours committer le lockfile mis à jour, sinon le prochain scan retrouve la même version.

### Cas 2 — Misconfiguration
Ouvrir le fichier/ressource indiqué et appliquer le correctif minimal (chiffrement activé, accès restreint, pas de privilèges larges). Détails dans le playbook IaC.

### Cas 3 — Secret
Ne PAS se contenter de supprimer la ligne : révoquer/rotater la valeur chez le provider, puis externaliser (variable d'environnement / secrets manager). Détails dans le playbook Secrets.

### Vérification locale
```bash
trivy fs --scanners vuln,misconfig,secret --severity CRITICAL,HIGH,MEDIUM .
```
Puis commit/push et relancer l'analyse depuis la plateforme.

### Notes
- Un même paquet peut générer plusieurs CVE : la mise à jour d'une seule version en corrige souvent plusieurs d'un coup — traiter par paquet, pas par CVE.
- Si `fixedVersion` est vide : aucune version corrigée publiée — évaluer l'exposition réelle et documenter l'acceptation, ou remplacer la dépendance.
