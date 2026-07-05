## Playbook: Secret / clé / token en dur (Gitleaks, Trivy, Semgrep)

### Quand ça arrive
- ScanType SECRETS (outil `gitleaks` en général) : une valeur sensible (API key, token, mot de passe, clé privée, ClientId…) est présente dans un fichier versionné.

### Ordre STRICT des opérations (l'ordre compte)
1) **RÉVOQUER / ROTATER d'abord** : si le secret est réel, il est déjà compromis (l'historique Git est public pour quiconque a accès au dépôt). Générer une nouvelle valeur dans la console du provider (AWS, GitHub, GitLab, Stripe…), invalider l'ancienne.
2) **Externaliser** : remplacer le littéral par une lecture de configuration (voir par stack ci-dessous).
3) **Stocker la nouvelle valeur hors du dépôt** : `.env` local non commité (dev) ; variables d'environnement runtime, Secrets Manager / Parameter Store, secrets CI (prod).
4) **Purger l'historique Git si le secret était réel** (sinon il reste lisible dans les anciens commits) :
```bash
# git-filter-repo (recommandé)
git filter-repo --replace-text <(echo "LA_VALEUR_SECRETE==>REDACTED")
git push --force-with-lease
```
   Prévenir l'équipe (réécriture d'historique). Si la rotation est faite et l'ancienne valeur invalidée, la purge devient moins critique mais reste une bonne pratique.
5) Vérifier le démarrage/build local, puis relancer l'analyse depuis la plateforme.

### Externalisation par stack (choisir selon PIPELINE_CONTEXT)

**Frontend SPA (React/Vite/Angular)** — ⚠ tout ce qui est dans le bundle est PUBLIC :
```js
const apiKey = import.meta.env.VITE_MY_KEY;   // Vite
const apiKey = process.env.REACT_APP_MY_KEY;  // CRA
```
Un vrai secret ne peut PAS vivre côté client : le déplacer derrière un backend/proxy. Les identifiants « publics par conception » (Cognito ClientId…) restent préférés via env injectée au build, pas en dur dans un fichier versionné.

**Node.js backend** : `process.env.MY_KEY` + `.env` dans `.gitignore` (dotenv en dev).

**Java / Spring Boot** :
```yaml
my:
  api-key: ${MY_API_KEY:}     # application.yml lit l'env var
```
puis `@Value("${my.api-key}")` — jamais le littéral dans application.yml commité.

**Python** : `os.environ["MY_KEY"]` (+ python-dotenv en dev). **.NET** : `builder.Configuration["MyKey"]` + user-secrets en dev, env vars en prod.

**Fichier privé complet commité** (clé SSH, keystore, .env) : le retirer, l'ajouter au `.gitignore`, purger l'historique, régénérer la clé.

### Interdits absolus
- Remplacer la valeur par une « nouvelle clé » en dur : même problème dans un mois.
- Supprimer la ligne sans rotation : le secret reste dans l'historique ET actif.
- Committer le `.env` « temporairement ».

### Vérification locale
```bash
gitleaks detect --source . -v          # dépôt courant
gitleaks detect --source . --log-opts="--all"   # inclut l'historique
```

### Notes
- Faux positifs fréquents : exemples de doc, valeurs de test, hash. Si c'en est un, l'exclure via `.gitleaks.toml` (allowlist) avec justification.
- Le rapport JSON du scan (`reports/...`) n'est pas le fichier à corriger : le finding pointe le fichier source d'origine.
