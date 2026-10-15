# Référence — ce que l'administrateur peut voir/faire en matière de sécurité

Date : 2026-08-31
But : répondre précisément à « l'admin fait quoi exactement ? », avec les endpoints/composants
réels — sert de source pour le chapitre 6 du rapport et pour vérifier qu'aucune information de
sécurité disponible côté backend ne reste invisible côté interface. Toutes les routes listées sont
sous `/api/admin/**`, protégées globalement par `hasAuthority("ROLE_ADMIN")` (`SecurityConfig`).

## 1. EnviroTest elle-même

| Capacité | Endpoint(s) | Composant(s) frontend |
|----------|-------------|------------------------|
| Créer un compte (email d'activation automatique) | `AdminController` (`CreateUserRequest`) | `admin/admin-users/*` |
| Lister les utilisateurs + stats d'activité individuelles | `AdminController` | `admin/admin-users/*` |
| Désactiver un compte | `AdminController` | `admin/admin-users/*` |
| Vue d'ensemble chiffrée (utilisateurs, apps, déploiements actifs) | `AdminController` | page d'accueil console admin |
| Consulter le journal d'audit (filtrable) | `AdminAuditController` | `admin/admin-audit/*` |
| Classement utilisateurs les plus actifs | `AdminAuditController` | `admin/admin-audit/*` |
| Connexions réussies vs échouées | `AdminAuditController` | `admin/admin-audit/*` |
| Activité admin vs utilisateurs standard | `AdminAuditController` | `admin/admin-audit/*` |
| **Lister les IP suspectes / bloquées automatiquement** | `GET /api/admin/security/blocked-ips` (`AdminSecurityController`) | `admin/admin-alerts/*` |
| **Bloquer manuellement une IP** (durée + motif) | `POST /api/admin/security/blocked-ips` | `admin/admin-alerts/*` |
| **Débloquer une IP** | `DELETE /api/admin/security/blocked-ips/{ip}` | `admin/admin-alerts/*` |
| **Résumé de protection des données** (TLS/HSTS actifs, algorithme et champs chiffrés au repos, secrets jamais stockés) | `GET /api/admin/security/data-protection` | `admin/admin-alerts/*` (à vérifier si affiché en détail — endpoint existant, contenu riche, sous-exploité visuellement) |
| Réclamations utilisateur (historique par fiche) | `AdminComplaintController` | `admin/admin-complaints/*` |

Le contenu exact de `data-protection` (`DataProtectionService.getProtectionSummary()`) :
- **En transit** : TLS 1.2+, HSTS (actif si `dataProtectionProperties.isHstsEnabled()`), en-têtes
  `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Cache-Control: no-store`.
- **Au repos (AES-256-GCM)** : `app_service.encrypted_github_token` (tokens GitHub),
  `users.totp_secret_enc` (secret 2FA), `users.password_hash` (bcrypt, irréversible par
  construction, distinct du chiffrement réversible des deux premiers).
- **Jamais stocké** : codes OTP par e-mail (mémoire, 5-10 min), jeton JWT (côté client uniquement).

Ce contenu existe déjà côté backend et remonte déjà au frontend (`admin.service.ts`) — non
vérifié ici s'il est intégralement affiché dans `admin-alerts` ou seulement consommé
partiellement ; à vérifier visuellement si le rapport doit s'appuyer dessus pour une capture
d'écran.

## 2. Applications déployées par les utilisateurs (chantier `audit-securite-apps-deployees.md`)

| Capacité | Endpoint(s) | Composant(s) frontend |
|----------|-------------|------------------------|
| Capacité de tous les nœuds du cluster (CPU/MEM/disque) | `GET /api/admin/monitoring/nodes` | `admin/admin-monitoring/*` |
| Résumé de tous les environnements RUNNING, tous utilisateurs (pods, alertes, propriétaire, orphelins) | `GET /api/admin/monitoring/namespaces` | `admin/admin-monitoring/*` |
| Détail complet d'un namespace au clic (pods, événements, quota, **isolation réseau**) | `GET /api/admin/monitoring/namespaces/{namespace}` | `admin/admin-monitoring/*` → `app-monitoring-dashboard` |
| **Isolation réseau active/absente** (nouveau, ce chantier) | inclus dans le détail ci-dessus (`networkPolicy`) | carte « Isolation réseau », `monitoring-dashboard.component.html` |
| Quota CPU/MEM alloué vs utilisé | inclus dans le détail ci-dessus (`quota`) | carte « Quota CPU/MEM » (préexistante) |

Point d'attention documenté dans `audit-securite-apps-deployees.md` §3, **non résolu ici** (décision
produit, pas un oubli technique) : rien dans la console admin n'indique aujourd'hui si le verdict
de sécurité d'une application déployée était `NON_RECOMMANDE` au moment du déploiement — l'admin
voit l'état runtime (pods, isolation, quota) mais pas la relation entre ce déploiement et le verdict
de sécurité qui l'a précédé.

## 3. Ce qui a été ajouté par ce chantier (31 août 2026)

- `K8sManifestApplyService.fetchNetworkPolicyStatus(namespace)` — relit la `NetworkPolicy`
  `default-isolation` réellement présente (pas seulement supposée envoyée), exposée dans
  `getNamespaceMonitoring()`.
- Carte « Isolation réseau » dans `monitoring-dashboard.component.ts/.html/.css` — visible dans la
  console admin ET dans le monitoring applicatif utilisateur (même composant partagé).
- `NetworkPolicyInfo` ajouté à `application-management.models.ts`.

## 4. Preuves — commandes

```bash
# Lister les IP bloquées (nécessite un jeton admin)
curl -s -H "Authorization: Bearer <JWT_ADMIN>" https://<host-envirotest>/api/admin/security/blocked-ips | jq

# Bloquer manuellement une IP de test
curl -s -X POST -H "Authorization: Bearer <JWT_ADMIN>" -H "Content-Type: application/json" \
  https://<host-envirotest>/api/admin/security/blocked-ips \
  -d '{"ip":"203.0.113.5","minutes":30,"reason":"test manuel"}'

# Consulter le résumé de protection des données
curl -s -H "Authorization: Bearer <JWT_ADMIN>" https://<host-envirotest>/api/admin/security/data-protection | jq

# Détail d'un namespace, avec isolation réseau (nouveau champ networkPolicy)
curl -s -H "Authorization: Bearer <JWT_ADMIN>" \
  https://<host-envirotest>/api/admin/monitoring/namespaces/<namespace> | jq '.networkPolicy, .quota'
```

---

*Document créé le 31 août 2026, en réponse directe à « l'admin fait quoi exactement, et si des
infos de sécurité ne sont pas affichées, ajoute-les ». Compagnon de
`audit-securite-apps-deployees.md`.*
