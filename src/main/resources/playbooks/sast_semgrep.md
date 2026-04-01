## Playbook: SAST (Semgrep)

### Quand ça arrive
- ScanType SAST
- Outil : `semgrep` (rapport JSON)

### Étapes
1) Ouvrir le fichier et la ligne indiqués par le finding (si présents).
2) Comprendre le pattern (ruleId) et vérifier si c’est un vrai positif.
3) Appliquer le correctif recommandé pour la famille (ex: XSS, SQLi, SSRF, secrets…).
4) Lancer tests/build local, puis relancer l’analyse depuis la plateforme.

### Vérification locale
```bash
# Relancer semgrep localement (si tu as semgrep installé)
semgrep scan --config auto --json -o semgrep.json .
```

### Notes
- Si le finding ne fournit pas de fichier/ligne, s’appuyer sur l’evidence_json (path, message, code snippet) ou coller l’extrait dans la plateforme pour une correction plus précise.

