## Playbook: DAST (OWASP ZAP)

### Quand ça arrive
- ScanType DAST, outil `zap` (baseline scan) contre l'**environnement éphémère déployé** (URL live) — pas contre le code source.

### La cible est l'application DÉPLOYÉE
- Le finding pointe une **URL/réponse HTTP**, jamais un fichier:ligne. On corrige la **configuration** (framework, serveur ou ingress) dans le dépôt, on redéploie, on re-scanne.
- Un seul correctif d'en-têtes règle souvent 4-5 alertes d'un coup.

### Alerte n°1 : en-têtes de sécurité manquants (CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy)
Choisir UNE couche d'application selon la stack (PIPELINE_CONTEXT) :

**Spring Boot (Spring Security)** :
```java
http.headers(h -> h
    .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
    .frameOptions(f -> f.deny())
    .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000)));
```

**Node/Express** :
```js
import helmet from "helmet";
app.use(helmet());   // pose CSP, X-Frame-Options, HSTS, noSniff, etc.
```

**Django** : `SECURE_HSTS_SECONDS`, `X_FRAME_OPTIONS = "DENY"`, `SECURE_CONTENT_TYPE_NOSNIFF = True` dans settings.py (+ django-csp). **ASP.NET** : middleware d'en-têtes dans `Program.cs`.

**SPA servie par nginx / Ingress K8s** (cas fréquent ici — l'app front n'a pas de « serveur » applicatif) :
```nginx
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "default-src 'self'" always;
```
ou annotations/`configuration-snippet` sur l'Ingress, versionnées dans le dépôt.

### Alerte n°2 : cookies sans attributs (Secure / HttpOnly / SameSite)
- Spring : `server.servlet.session.cookie.secure=true`, `.http-only=true`, `.same-site=lax`
- Express : options de `express-session` (`cookie: { secure: true, httpOnly: true, sameSite: "lax" }`)

### Alerte n°3 : divulgation d'information
Stack traces / pages d'erreur détaillées → désactiver en prod ; masquer `Server` / `X-Powered-By` (Express : `app.disable("x-powered-by")`).

### CSP : démarrer sans rien casser
Commencer en mode rapport : en-tête `Content-Security-Policy-Report-Only`, observer les violations, puis basculer en bloquant. Une CSP trop stricte posée d'un coup casse souvent les scripts/styles inline d'une SPA.

### Étapes
1) Identifier l'alerte ZAP exacte (nom + evidence) et l'URL testée.
2) Localiser la couche qui produit la réponse (framework applicatif, nginx, ingress).
3) Appliquer le correctif DANS LE DÉPÔT (config versionnée), commit/push.
4) Redéployer l'environnement puis relancer l'analyse depuis la plateforme (ZAP re-testera l'URL).

### Vérification locale
```bash
curl -sI https://mon-env.example.com | grep -iE "content-security|x-frame|strict-transport|x-content-type|referrer-policy|set-cookie"
```

### Notes
- Beaucoup d'alertes baseline sont Low/Info : prioriser CSP, HSTS, cookies avant le cosmétique.
- HSTS n'a de sens qu'en HTTPS ; sur un environnement éphémère en HTTP, certaines alertes sont structurelles à l'environnement, pas au code — le signaler plutôt qu'inventer un correctif.
