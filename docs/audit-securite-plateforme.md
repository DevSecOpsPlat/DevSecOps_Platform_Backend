# Audit — Auto-protection d'EnviroTest (identité, détection d'intrusion)

Date : 3 septembre 2026
Périmètre : chapitre 6 du rapport, section "Identité et auto-protection contre les attaques" —
JWT, double authentification, détection de menaces, limitation de débit, Nginx.
Règle : chaque affirmation est sourcée (fichier + classe) ; sinon « introuvable dans le code ».

> Ce document n'existait pas avant ce chantier — c'est le premier `.md` dédié à ce que la
> plateforme fait pour **se protéger elle-même**, distinct de `audit-quality-gate.md` (score des
> applications scannées) et de `audit-securite-apps-deployees.md` (isolation runtime des
> applications déployées).

## 1. Authentification et double authentification (2FA)

- **JWT** : `JwtFilter` — jeton à durée de vie limitée (24 heures).
- **2FA obligatoire pour TOUT compte**, pas seulement les comptes administrateur —
  `TwoFactorEnforcementFilter` (javadoc, L21-23) : *"Bloque l'accès API tant que la 2FA n'est pas
  configurée (obligatoire pour tous les comptes)."* Tant qu'un utilisateur n'a pas activé sa 2FA
  (TOTP ou e-mail), toute route API renvoie 403 sauf la liste `ALLOWED_WITHOUT_2FA` (profil,
  endpoints de configuration 2FA eux-mêmes).
  **Correction apportée au rapport le 3 septembre 2026** : le texte précédent limitait par erreur
  cette obligation aux comptes administrateur.

## 2. Détection de menaces — `ThreatDetectionService`

Cinq catégories (`ThreatCategory`), analysées dans cet ordre sur chaque requête (chemin + query +
User-Agent) :

| Catégorie | Détection | `blockImmediately` |
|---|---|---|
| `HONEYPOT` | Chemin exact dans `HONEYPOT_PATHS` (`/admin/secret`, `/.env`, `/wp-admin`, `/wp-login.php`, `/phpmyadmin`, `/actuator/env`, `/.git/config`, `/cgi-bin/`, `/etc/passwd`) | `true` |
| `SUSPICIOUS_URL` | Fragment dans `SUSPICIOUS_PATH_FRAGMENTS` (`.env`, `.git`, `wp-admin`, `wp-login`, `phpmyadmin`, `web.config`, `shell.php`, `cmd.exe`, `../`, `..\`, `%2e%2e`, `/actuator/`, `/server-status`, `/.aws/`, `/config.json`) | `true` |
| `SQL_INJECTION` | 8 regex (`SQL_PATTERNS`) : `' or '1`, `or 1=1`, `--$`, `; drop`, `union select`, `sleep(`, `benchmark(`, `information_schema` | `true` |
| `XSS` | 5 regex (`XSS_PATTERNS`) : `<script`, `javascript:`, `on(error|load|click|mouse)=`, `<iframe`, `document.cookie` | `true` |
| `SUSPICIOUS_USER_AGENT` (signature connue, sur endpoints sensibles uniquement) | UA contient un nom d'outil dans `SCANNER_USER_AGENTS` (sqlmap, nikto, nmap, masscan, dirbuster, gobuster, hydra, metasploit, wpscan, acunetix, nessus, burpsuite, zaproxy, python-requests/, libwww-perl) | `true` |
| `SUSPICIOUS_USER_AGENT` (absent/vide) | Pas de header `User-Agent` | `false` (flag seulement) |

**Point important, vérifié dans `SecurityMonitoringService.handleThreat()` (L62-66)** : TOUTE
catégorie avec `blockImmediately=true` déclenche **le même blocage IP de 60 minutes**
(`properties.getBlocklist().getHoneypotBlockMinutes()`), pas seulement les chemins honeypot — la
requête en cours est aussi refusée (403 "Requête refusée", `SecurityMonitoringFilter` L95-98).
**Correction apportée au rapport** : le tableau `tab:attaques` indiquait par erreur "IP signalée"
(sans blocage) pour l'injection SQL, le XSS et les outils de scan automatisés — en réalité, ces
trois catégories bloquent l'IP 60 minutes comme la reconnaissance de chemins sensibles.

## 3. Limitation de débit — `SecurityMonitoringProperties.RateLimit` + `Bucket4jRateLimitService`

| Portée | Limite | Fenêtre |
|---|---|---|
| Globale (toute IP) | 200 requêtes | 60 s |
| `/auth/login` | 20 requêtes | 60 s |
| `/api/admin/**` | 100 requêtes | 60 s |

**Point important, vérifié dans `SecurityMonitoringService.handleRateLimitExceeded()` (L69-85)** :
CHAQUE dépassement (pas seulement en cas de répétition) déclenche un blocage IP de 15 minutes
(`properties.getBlocklist().getRateLimitBlockMinutes()`), en plus du rejet HTTP 429 immédiat.
**Correction apportée au rapport** : le tableau ne mentionnait aucun blocage IP pour cette
catégorie — seulement "rejetées, alerte".

## 4. Force brute — `SecurityMonitoringProperties.BruteForce`

5 échecs de connexion par IP en 1 minute → IP bloquée 30 minutes
(`handleBruteForceDetected()`). Déjà exact dans le rapport avant ce chantier.

## 5. En-têtes de sécurité et transport

Vérifié dans `DataProtectionService.getProtectionSummary()` (déjà documenté dans
`admin-securite-reference.md` §1) : `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy`, `Cache-Control: no-store` sur l'API. HSTS et
l'imposition HTTPS sont pilotés par des propriétés (`dataProtectionProperties`), actives en
production.

## 6. Nginx — première ligne de défense

`deploy/nginx/envirotest.docker.conf` / `envirotest.conf` (ce dernier est celui réellement utilisé
en production sur cette installation -- écoute `127.0.0.1:8089`/`:4200`, cohérent avec
`docker-compose.yml` ; le service Docker `nginx` de `envirotest.docker.conf`, lui, n'est pas démarré
sur cette instance) :
- mêmes chemins-pièges bloqués une couche avant le backend Spring ;
- masquage de la documentation d'API (`/swagger-ui`, `/v3/api-docs`) en production ;
- premier niveau de limitation de débit ;
- **ajouté le 4 septembre 2026** : filtrage par motifs (`map $request_uri $waf_pattern_block`)
  reprenant les mêmes signatures que `ThreatDetectionService.java` (SQL_PATTERNS/XSS_PATTERNS),
  avec tolérance à l'encodage URL le plus courant (`%20`, `+`, `%27`, `%3C`) — testé en direct
  (conteneur Nginx jetable + `curl`) : bloque `' OR 1=1--`, `UNION SELECT`, `<script>` (bruts et
  encodés) en 403, sans jamais toucher un trafic normal contenant un espace ou une apostrophe
  légitime dans une valeur.

**Toujours pas un WAF au sens strict (type ModSecurity/OWASP CRS)** : pas d'inspection du corps de
la requête, pas de moteur de règles, encodage exotique (double encodage, hex lettre par lettre) non
couvert — une couche de filtrage par motifs, positionnée avant Spring pour écarter le cas le plus
grossier sans jamais solliciter la JVM, le filtre applicatif restant la ligne de défense de
référence. Un vrai bannissement réseau façon fail2ban reste absent (identifié comme évolution
possible, non retenu pour ce stage). La figure `fig:defense-en-profondeur` du rapport ne représente
donc pas de bloc "Firewall/WAF" séparé — seul Nginx (avec ses responsabilités réelles) précède la
chaîne de filtres Spring (`SecurityMonitoringFilter` → `JwtFilter` → `TwoFactorEnforcementFilter`),
ordre confirmé par le log de démarrage Spring Security (`DefaultSecurityFilterChain`, capturé en
direct sur `envirotest-backend`).

## 7. Fonctionnalité retirée — export PDF

`ENV-507` ("exporter un rapport de scan au format PDF") a été retiré du backlog du chapitre 6 :
recherché explicitement, **aucun contrôleur** n'implémente `/api/reports/**` (seule une règle de
permission + un commentaire subsistent dans `SecurityConfig.java` L114-115), et le frontend ne
contient plus aucune référence à un export PDF. Fonctionnalité confirmée absente de l'application
actuelle.

## 8. Fichiers clés

| Fichier | Rôle |
|---|---|
| `configuration/SecurityMonitoringFilter.java` | Chaîne de détection + rate limiting, avant JWT |
| `configuration/SecurityMonitoringProperties.java` | Tous les seuils numériques (brute force, rate limit, blocklist) |
| `configuration/TwoFactorEnforcementFilter.java` | Blocage API tant que la 2FA n'est pas configurée (tout compte) |
| `configuration/JwtFilter.java` | Vérification du jeton |
| `service/security/monitoring/ThreatDetectionService.java` | Motifs honeypot/URL suspecte/SQLi/XSS/User-Agent |
| `service/security/monitoring/SecurityMonitoringService.java` | Alertes, journal d'audit, application des blocages IP |
| `service/security/monitoring/IpBlocklistService.java` | Blocklist IP (lecture/écriture, blocage manuel admin) |
| `service/security/DataProtectionService.java` | Résumé chiffrement transit/repos, en-têtes de sécurité |
| `controller/admin/AdminSecurityController.java` | `/api/admin/security/blocked-ips`, `/data-protection` |
| `deploy/nginx/envirotest.docker.conf` / `envirotest.conf` | Première ligne de défense (chemins-pièges, doc API masquée, rate limit, filtrage SQLi/XSS par motifs) |
| `service/appmgmt/AppK8sManifestService.java` (`containerSecurityContext()`) | `securityContext` conteneur (sous-ensemble sûr partout + durcissement opt-in) — chantier des apps déployées, pas EnviroTest elle-même |
| `entity/AppService.java` (`hardenedSecurityContext`) | Flag opt-in par service, désactivé par défaut |
