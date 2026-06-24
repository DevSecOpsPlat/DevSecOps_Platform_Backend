## Playbook: Problème de licence (License scanning / compliance)

### Quand ça arrive
- Le scanner signale une dépendance avec une licence **interdite**, **incompatible** ou **inconnue** (ex. `GPL-3.0` dans un produit propriétaire, licence manquante, dual licensing).
- Le finding est souvent au niveau **package** (pas au niveau fichier/ligne).

### Objectif
Réduire le risque légal/compliance sans casser le projet :
- identifier la dépendance concernée,
- confirmer la licence exacte,
- décider : **remplacer**, **mettre à jour**, **retirer**, ou **accepter avec justification**.

### Important : ce n'est pas une vulnérabilité “attaquant”
- Un finding **LICENSE** n’est généralement **pas un risque de sécurité** : pas de “attaquant”, pas de XSS, etc.
- L’impact est surtout **légal / conformité / distribution** (ex. obligations copyleft, compatibilité, politique interne).
- **MIT / Apache-2.0 / BSD** sont en général **permissives** et **souvent OK**. Il n’y a “problème” que si votre politique l’interdit (rare) ou si la licence détectée est erronée.

### Étapes (génériques)
1) **Sanity check** : vérifier que l’élément signalé est bien une **vraie dépendance** du projet (et pas un libellé erroné du scanner).
   - Exemple : `amany@5.1.0` ressemble à un format “nom@version”, mais il faut confirmer que `amany` existe dans votre lockfile / arbre de dépendances.
2) Confirmer la licence réelle (SPDX) dans les sources officielles du package (ou dans sa page registry).
3) Décider selon la politique :
   - Licence permissive (MIT/Apache/BSD) autorisée → **documenter/accept**.
   - Licence interdite/incompatible ou inconnue → **remplacer / retirer / mettre à jour / whitelister** (avec justification).
4) Appliquer la correction dans le dépôt, vérifier build/tests, puis **relancer l’analyse depuis la plateforme**.

### Commandes utiles (adapter à la stack)
```bash
# Node.js
npm ls <package>            # confirme que le package est réellement présent
npm view <package> license  # confirme la licence (si le package existe sur npm)

# Maven (si la dépendance est Maven)
mvn -q dependency:tree | grep -i "<artifactId>"

# Python
python -m pip show <package>
```

### Notes
- Une alerte “licence inconnue” peut venir d’une dépendance transitive : la vraie action est souvent de mettre à jour le parent.
- Si tu dois générer un rapport : créer une entrée dans `THIRD_PARTY_NOTICES` / `NOTICE` selon ta politique.

