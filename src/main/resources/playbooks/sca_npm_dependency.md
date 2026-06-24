## Playbook: Dépendance vulnérable (Node.js / npm / yarn / pnpm)

### Quand ça arrive
- ScanType SCA / Dependency scanning (npm audit, osv, etc.)
- Le finding pointe un **package** + version (`packageName`, `installedVersion`, `fixedVersion`).

### Étapes
1) Vérifier la dépendance exacte et sa version dans le lockfile (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`).
2) Mettre à jour vers une version corrigée (si `fixedVersion` est fournie, la viser).
3) Vérifier que l’app compile et que les tests passent.
4) Relancer l’analyse depuis la plateforme.

### Commandes utiles (adapter selon manager)
```bash
# npm
npm ls <package>
npm audit --production
npm install <package>@<version_corrigée>
npm audit fix

# yarn
yarn why <package>
yarn upgrade <package>@<version_corrigée>

# pnpm
pnpm why <package>
pnpm up <package>@<version_corrigée>
```

### Notes
- Si la mise à jour majeure casse l’API, proposer une alternative : patch mineur + mitigation (feature flag) + plan de migration.
- Si le package est transitive : agir sur le parent (update parent) ou utiliser overrides/resolutions.

