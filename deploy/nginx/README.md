# Nginx — couche reverse proxy EnviroTest

Deux couches de rate limiting complémentaires :

| Couche | Outil | Rôle |
|--------|-------|------|
| **Serveur** | Nginx `limit_req` | Première ligne — absorbe floods, scans, DDoS léger avant la JVM |
| **Application** | Bucket4j (Spring) | Limites fines par endpoint (`/auth/login`, `/api/admin`) + alertes + blocage IP en BD |

## Architecture

```
Client → Nginx :8081 → Angular (/) ou Spring (/projet/) ou Grafana (/grafana/)
                              ↓
                    X-Real-IP / X-Forwarded-For
                              ↓
                    SecurityMonitoringFilter + Bucket4j + blocked_ips
```

## Fichiers

- `envirotest.conf` — configuration principale
- `proxy-headers.conf` — en-têtes IP réelle pour Spring

## Installation Linux

```bash
sudo mkdir -p /etc/nginx/conf.d
sudo cp deploy/nginx/proxy-headers.conf /etc/nginx/conf.d/
sudo cp deploy/nginx/envirotest.conf /etc/nginx/conf.d/

# Si envirotest.conf est un fichier complet (events + http), l'inclure depuis nginx.conf :
# include /etc/nginx/conf.d/envirotest.conf;

sudo nginx -t
sudo systemctl reload nginx
```

## Installation Windows (nginx portable)

1. Télécharger nginx : https://nginx.org/en/download.html
2. Copier `proxy-headers.conf` → `nginx/conf/conf.d/`
3. Copier le contenu de `envirotest.conf` ou l'inclure depuis `nginx.conf`
4. `nginx -t` puis `nginx -s reload`

## Points d'accès

| URL | Cible |
|-----|-------|
| http://localhost:8081/ | Angular (dev :4200) |
| http://localhost:8081/projet/auth/login | Spring Boot |
| http://localhost:8081/projet/api/admin/ | API admin |
| http://localhost:8081/grafana/ | Grafana VM |

## Configuration Spring (application.properties)

Derrière Nginx, Spring reçoit la vraie IP via `X-Forwarded-For` (déjà géré par `IpAddressUtils`).

```properties
app.security.trust-localhost=false
server.forward-headers-strategy=framework
```

## Rate limits Nginx (défaut)

| Zone | rate | burst | Usage |
|------|------|-------|-------|
| `global_limit` | 100 req/min | 20 | `/projet/*`, frontend |
| `login_limit` | 20 req/min | 5 | `POST /projet/auth/login` |
| `admin_limit` | 60 req/min | 15 | `/projet/api/admin/*` |
| `conn_limit` | 50 conn/IP | — | connexions simultanées |

Réponse en dépassement : **HTTP 429** (`limit_req_status 429`).

## Autres protections incluses

- `server_tokens off` — masque la version Nginx
- `client_max_body_size 10m` — limite uploads
- Blocage `.env`, `.git`, `wp-admin`, honeypot `/admin/secret`
- Swagger bloqué en prod (`/projet/swagger-ui`, `/projet/v3/api-docs`)
- En-têtes : `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`
- Logs format `security` pour corrélation avec alertes Spring

## Production bancaire (recommandations supplémentaires)

1. **HTTPS** — certificat TLS (Let's Encrypt ou PKI interne) + `listen 443 ssl`
2. **HSTS** — décommenter `Strict-Transport-Security`
3. **fail2ban** — bannir IP après N× 429/403 dans les logs Nginx
4. **ModSecurity** (optionnel) — WAF Nginx plus avancé
5. **Angular en statique** — `ng build` servi par Nginx (bloc commenté dans la conf)
6. **Réseau** — Spring `:8089` accessible **uniquement** depuis localhost (firewall)

## Test rate limit Nginx

```powershell
# 25 requêtes rapides sur login → certaines en 429 (avant même Spring)
1..25 | ForEach-Object {
  curl.exe -s -o NUL -w "%{http_code}`n" http://localhost:8081/projet/auth/login -X POST -H "Content-Type: application/json" -d "{}"
}
```

## Frontend Angular

En prod, pointer l'API vers le même hôte Nginx (pas le port 8089 direct) :

```typescript
// environments/environment.prod.ts
export const environment = {
  apiUrl: '/projet'   // même origine → pas de CORS
};
```
