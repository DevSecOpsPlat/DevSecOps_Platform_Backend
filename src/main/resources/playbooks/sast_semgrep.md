## Playbook: SAST (Semgrep — tous langages)

### Quand ça arrive
- ScanType SAST, outil `semgrep` : un **pattern de code dangereux** est détecté dans un fichier source (fichier + ligne + ruleId en général fournis).

### Démarche universelle
1) Ouvrir le fichier:ligne du finding et lire le `ruleId` (il nomme la famille : ex. `javascript.express.security.injection...`).
2) **Trier vrai/faux positif** : le pattern est-il atteignable avec des données contrôlées par l'utilisateur ? Une concaténation SQL sur une constante n'est pas exploitable ; sur un paramètre HTTP, si.
3) Appliquer le correctif de la **famille** (ci-dessous), adapté au langage du fichier (voir PIPELINE_CONTEXT).
4) Build + tests locaux, commit/push, relancer l'analyse depuis la plateforme.

### Correctifs par famille (multi-langages)

**Injection SQL** — ne jamais concaténer l'entrée utilisateur dans la requête :
- Java : `PreparedStatement` / paramètres JPA (`:param`) — jamais `"... WHERE id=" + id`
- Node : requêtes paramétrées (`pool.query('... WHERE id = $1', [id])`), ORM
- Python : `cursor.execute("... WHERE id = %s", (id,))`, ORM ; C#: paramètres `SqlCommand`/EF

**XSS** — encoder à la sortie, pas filtrer à l'entrée :
- Angular/React : rester dans le binding par défaut ; bannir `innerHTML`/`dangerouslySetInnerHTML` (ou assainir avec DOMPurify)
- Templates serveur (Thymeleaf, Jinja2, Blade) : utiliser l'échappement par défaut, ne pas marquer `safe`/`raw` des données utilisateur

**SSRF** — valider l'URL cible côté serveur : liste d'autorisation d'hôtes/schémas, résolution DNS contrôlée, pas d'URL brute venant du client dans `fetch`/`HttpClient`/`requests`.

**Path traversal** — normaliser puis vérifier le préfixe :
- Java : `Path.of(base).resolve(name).normalize().startsWith(base)`
- Node : `path.resolve(base, name)` + vérif `startsWith(base)` ; Python : `os.path.realpath` + vérif préfixe

**Désérialisation non sûre** — jamais `pickle.loads` / `ObjectInputStream` / `BinaryFormatter` sur des données non fiables ; préférer JSON + validation de schéma.

**Crypto faible** — remplacer MD5/SHA1 (usage sécurité) par SHA-256+, `Math.random()`/`random` par `SecureRandom` / `crypto.randomBytes` / `secrets` ; mots de passe → bcrypt/argon2.

**Commande système** — pas de shell avec chaîne concaténée : passer les arguments en tableau (`ProcessBuilder`, `execFile`, `subprocess.run([...], shell=False)`).

### Si c'est un faux positif avéré
Documenter et supprimer localement avec un commentaire `// nosemgrep: <ruleId>` sur la ligne (avec justification en revue) — ne pas en abuser.

### Vérification locale
```bash
semgrep scan --config auto --severity ERROR .
```
Puis relancer l'analyse depuis la plateforme.

### Notes
- Si le finding ne fournit pas fichier/ligne, s'appuyer sur l'evidence (path, message, extrait) ou coller l'extrait dans « Affiner l'analyse ».
- Corriger la famille partout dans le fichier, pas seulement la ligne signalée : Semgrep ne remonte parfois qu'une occurrence.
