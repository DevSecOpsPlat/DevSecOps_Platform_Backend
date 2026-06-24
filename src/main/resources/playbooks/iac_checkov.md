## Playbook: IaC / misconfiguration (Checkov)

### Quand ça arrive
- ScanType IAC
- Outil : `checkov` (Terraform/K8s YAML, etc.)

### Étapes
1) Ouvrir le fichier IaC et la ressource indiquée (si path/ligne fournis).
2) Comprendre la règle (ex: bucket public, encryption off, RBAC permissif).
3) Appliquer le correctif minimal (principe du moindre privilège) :
   - activer chiffrement,
   - restreindre accès réseau,
   - fixer IAM/RBAC,
   - activer logs/audit.
4) Valider le plan/apply (si applicable) et relancer l’analyse depuis la plateforme.

### Vérification locale
```bash
checkov --directory . --output json
```

