## Playbook: Subresource Integrity (SRI) manquant (`integrity`)

### Quand ça arrive
- Balises HTML/templating qui chargent des ressources externes (CDN) :
  - `<script src="https://...">`
  - `<link rel="stylesheet" href="https://...">`
- Le scanner signale : **"This tag is missing an 'integrity' subresource integrity attribute"**.

### But
Garantir que le navigateur n’exécute/charge la ressource **que si son hash correspond** (protection contre compromission CDN / MITM).

### Étapes (génériques)
1) Identifier l’URL exacte de la ressource (dans le fichier et la ligne signalés).
2) Télécharger la ressource **exactement** telle qu’elle sera servie (même URL/version).
3) Calculer un hash (préférer **SHA-384** ou SHA-256) et l’encoder en base64.
4) Ajouter l’attribut `integrity="sha384-..."` (ou sha256) à la balise.
5) Ajouter `crossorigin="anonymous"` pour les ressources cross-origin (recommandé avec SRI).
6) Vérifier en local (build + ouverture page) puis relancer le scan depuis la plateforme.

### Commandes (Windows/Unix) — exemple SHA-384
```bash
# Téléchargement
curl -L -o resource.min.css "https://example-cdn.com/lib/1.2.3/resource.min.css"

# Hash SHA-384 en base64 (openssl)
openssl dgst -sha384 -binary resource.min.css | openssl enc -base64 -A
```

### Exemple de correctif (copiable)
```html
<link
  rel="stylesheet"
  href="https://example-cdn.com/lib/1.2.3/resource.min.css"
  integrity="sha384-BASE64_HASH_ICI"
  crossorigin="anonymous"
/>
```

```html
<script
  src="https://example-cdn.com/lib/1.2.3/resource.min.js"
  integrity="sha384-BASE64_HASH_ICI"
  crossorigin="anonymous"
></script>
```

### Notes importantes
- Si la ressource change (version “latest”, fichier modifié côté CDN), **le hash doit être recalculé**.
- Pour des bundles générés (Webpack/Vite/Angular) : si c’est toi qui sers le fichier depuis ton serveur, SRI n’est pas forcément requis (scanner dépend du contexte). Le playbook s’applique aux **URLs externes**.

