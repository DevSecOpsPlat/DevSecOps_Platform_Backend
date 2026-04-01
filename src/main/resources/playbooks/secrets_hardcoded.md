## Playbook: Secret/clé/token en dur détecté

### Objectif
Retirer la valeur sensible du dépôt, sans casser l’app.

### Étapes
1) Révoquer/rotater le secret exposé (console du provider) si c’est un vrai secret.
2) Remplacer dans le code par une **lecture de variable d’environnement** (placeholder).
3) Stocker la valeur dans un endroit adapté :
   - `.env.local` non commité (dev)
   - Secrets Manager / Parameter Store / variables d’environnement runtime (prod)
4) Vérifier le démarrage/local build.
5) Relancer l’analyse depuis la plateforme.

### Exemples (placeholders)
```js
// Exemple Node/Front build: utiliser des env injectées (selon framework)
const apiKey = process.env.MY_API_KEY;
```

```bash
# Exemple local (NE PAS commiter)
export MY_API_KEY="valeur"
```

### Notes
- Ne jamais remplacer une clé par une “nouvelle-clé” en dur.
- Pour SPA (React/Vite/Angular) : les variables côté client sont publiques, donc secrets réels → backend ou proxy, sinon token public limité.

