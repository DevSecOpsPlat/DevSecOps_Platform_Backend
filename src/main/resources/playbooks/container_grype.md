## Playbook: Container scan (Grype)

### Quand ça arrive
- ScanType CONTAINER
- Outil : `grype` sur une image Docker construite depuis le dépôt

### Étapes
1) Identifier si la vulnérabilité vient de :
   - image de base (`FROM ...`)
   - packages OS (apk/apt/yum)
   - dépendances applicatives embarquées
2) Corriger :
   - mettre à jour l’image de base (tag plus récent)
   - mettre à jour les packages OS (`apk upgrade`, `apt-get update && apt-get upgrade`)
   - mettre à jour les libs applicatives (npm/maven/pip) si incluses
3) Rebuild l’image localement et relancer l’analyse depuis la plateforme.

### Vérification locale
```bash
docker build -t app-image:test .
grype app-image:test --output json > grype.json
```

