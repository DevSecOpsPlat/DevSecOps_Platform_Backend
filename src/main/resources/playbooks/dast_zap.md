## Playbook: DAST (OWASP ZAP)

### Quand ça arrive
- ScanType DAST, outil `zap` (baseline scan) contre l'**application déployée** (URL publique) — pas contre le code source.
- ZAP observe des réponses HTTP (en-têtes, cookies, contenu). Il ne connaît ni le framework, ni le fichier responsable.

### Ce qui est un fait, ce qui est à vérifier
- Fait : « la réponse de l'URL X ne contient pas l'en-tête Y » (constat ZAP, éventuellement revérifié par le contrôle HTTP de la plateforme).
- À vérifier : quel composant devrait poser l'en-tête, et si une configuration existe déjà ailleurs.
- Ne jamais présenter un fichier (main.py, SecurityConfig.java…) comme responsable sans l'avoir lu.

### Chaîne d'exposition sur EnviroTest
1. **Cloudflare** (tunnel) : TLS public, proxy. Peut ajouter HSTS (réglage de la zone) — administrateur de la plateforme.
2. **Traefik** : Ingress Kubernetes **généré par EnviroTest** (routage, strip de préfixe). Il n'ajoute aucun en-tête de sécurité et n'est **pas dans le dépôt** du développeur — un middleware d'en-têtes est une option à demander à l'administrateur.
3. **Conteneur de l'application** : l'application elle-même (ou le nginx d'une SPA). C'est le seul niveau que le développeur modifie dans son dépôt ; les en-têtes qu'il pose sont relayés tels quels.

### Correctif au niveau application (quand la technologie est connue)
**FastAPI / Starlette** :
```python
@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    return response
```

**Spring Boot (Spring Security)** :
```java
http.headers(h -> h
    .contentTypeOptions(Customizer.withDefaults())
    .httpStrictTransportSecurity(hsts -> hsts.maxAgeInSeconds(31536000)));
```

**Node/Express** : `helmet()` (vérifier sa CSP par défaut avant de l'activer en production).

**SPA servie par nginx** :
```nginx
add_header X-Content-Type-Options "nosniff" always;
```

### Cas particuliers
- **HSTS** : n'a d'effet qu'en HTTPS. `max-age=31536000` ; `includeSubDomains` seulement si tous les sous-domaines sont en HTTPS ; jamais `preload` par défaut. Sur EnviroTest, TLS est terminé par Cloudflare : HSTS peut être posé par Cloudflare (administrateur) ou par l'application.
- **CSP** : partir des ressources réellement chargées (scripts, styles, polices, API, images). Commencer par `Content-Security-Policy-Report-Only`, observer les violations, puis passer en mode bloquant. Une CSP stricte posée d'un coup casse souvent les scripts/styles inline d'une SPA. Si une CSP existe déjà, la compléter.
- **CORS** (Cross-Domain Misconfiguration) : regarder `Access-Control-Allow-Origin` et `Access-Control-Allow-Credentials` réellement renvoyés. `*` sans credentials sur des ressources publiques n'est pas exploitable en soi ; c'est grave si l'origine est reflétée avec `credentials: true` ou si des données privées sont servies.
- **Anti-clickjacking** : si une CSP existe, ajouter `frame-ancestors 'none'` (ou `'self'`) à cette CSP sans écraser ses autres directives ; `X-Frame-Options: DENY` en complément pour les anciens navigateurs.
- **Cookies** (Secure / HttpOnly / SameSite) : configuration de session de l'application.
- **Divulgation d'information** (Server, X-Powered-By) : sévérité faible.

### Étapes
1) Lire l'alerte ZAP (nom, URL testée) et le contrôle HTTP de la plateforme.
2) Identifier la couche qui doit poser l'en-tête et vérifier qu'aucune configuration existante ne l'écrase.
3) Corriger dans le dépôt (application) ou demander le réglage à l'administrateur (Cloudflare / Ingress).
4) Redéployer puis relancer l'analyse depuis la plateforme (ZAP re-testera l'URL).

### Vérification
```bash
curl -sI https://mon-app.envirotest.cloud/ | grep -iE "content-security|x-frame|strict-transport|x-content-type|referrer-policy|access-control|set-cookie"
```

### Notes
- Beaucoup d'alertes baseline sont Low/Info : prioriser CSP, cookies et CORS réellement exploitables avant le cosmétique.
- Un seul middleware d'en-têtes règle souvent plusieurs alertes d'un coup.
