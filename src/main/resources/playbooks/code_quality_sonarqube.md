## Playbook: Qualité de code & hotspots (SonarQube)

### Quand ça arrive
- Outil : `sonarqube` (analyse au stage code-analysis du pipeline).
- Trois familles de findings : **Bug** (fiabilité), **Code Smell** (maintenabilité), **Security Hotspot / Vulnerability** (sécurité).

### Bien qualifier le finding
1) **Vulnerability** : problème de sécurité avéré → traiter comme un finding SAST (corriger le pattern).
2) **Security Hotspot** : code *sensible* à **revoir**, pas forcément vulnérable (ex. usage de `Math.random()`, exécution de commande, CORS). L'action peut être « corriger » OU « marquer comme sûr avec justification » après revue.
3) **Bug / Code Smell** : pas un risque attaquant ; impact = fiabilité/maintenabilité (NPE potentielle, complexité cognitive, code mort, duplication).

### Étapes
1) Ouvrir le fichier et la ligne indiqués ; lire la règle Sonar (ex. `java:S2245`) et son rationale.
2) Vérifier si c'est un vrai positif dans CE contexte (les hotspots sont souvent des faux positifs contextuels).
3) Appliquer le correctif recommandé par la règle (renommage, extraction de méthode, null-check, API sécurisée type `SecureRandom`, etc.).
4) Lancer build + tests en local, commit/push, puis relancer l'analyse depuis la plateforme.

### Vérification locale
```bash
# Build + tests selon la stack
mvn -q test          # Java/Maven
npm test             # Node
```

### Notes
- Pour un Code Smell, ne pas dramatiser : l'impact est la dette technique, pas une attaque. Adapter le ton du diagnostic.
- La complexité cognitive se corrige par extraction de méthodes courtes et retours anticipés (early return), pas en supprimant la logique.
- Si la règle semble inadaptée au projet, la bonne pratique est de la commenter/justifier plutôt que de contourner le code.
