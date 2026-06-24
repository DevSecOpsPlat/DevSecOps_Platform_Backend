## Playbook: Trivy FS (SCA / vuln / secret / config)

### Quand ça arrive
- Outil : `trivy fs` sur le dépôt
- Peut produire des findings de type : vuln packages, misconfig, secrets, etc.

### Étapes
1) Lire le finding : type (vuln/config/secret), fichier, package, et recommandation.
2) Si package vulnérable : appliquer le playbook SCA adapté (npm/maven/python…).
3) Si misconfig (IaC) : appliquer le playbook IaC (Checkov-like).
4) Si secret : appliquer le playbook Secrets.
5) Vérifier build/tests puis relancer l’analyse depuis la plateforme.

### Vérification locale
```bash
trivy fs --format json --output trivy.json --severity CRITICAL,HIGH,MEDIUM .
```

