## Playbook: Dépendance vulnérable (Python / pip-audit / safety)

### Quand ça arrive
- ScanType SCA
- Outils typiques : `pip-audit`, `safety`, trivy (mode fs) sur requirements.

### Étapes
1) Identifier la dépendance (nom + version installée) et l’ID (CVE/OSV) si présent.
2) Vérifier dans `requirements.txt`, `pyproject.toml` ou l’outil de gestion (Poetry/Pipenv) si la dépendance est directe ou transitive.
3) Mettre à jour vers une version corrigée (si `fix_versions`/`fixedVersion` est fourni, la viser).
4) Exécuter tests/linters puis relancer l’analyse depuis la plateforme.

### Commandes utiles
```bash
python -m pip show <package>
python -m pip install -U <package>

# Si requirements.txt
pip-audit --requirement requirements.txt --format json
safety check --file requirements.txt --json
```

### Notes
- Pour dépendances transitives : mettre à jour le parent, ou régénérer le lock (Poetry/Pipenv).

