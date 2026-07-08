## Playbook: IaC / misconfiguration (Checkov)

### Quand ça arrive
- ScanType IAC, outil `checkov` : une ressource d'infrastructure déclarée dans le dépôt viole une règle (`CKV_...`). Cibles possibles : Terraform (.tf), Kubernetes YAML, Dockerfile, docker-compose, CloudFormation, Helm.

### Démarche
1) Ouvrir le fichier + la ressource indiqués ; lire l'ID de la règle (`CKV_AWS_20`, `CKV_K8S_22`…) — le préfixe dit la techno.
2) Comprendre ce que la règle protège, appliquer le **correctif minimal** (moindre privilège) ci-dessous.
3) Valider la syntaxe localement, commit/push, relancer l'analyse depuis la plateforme.

### Familles fréquentes et correctifs

**Kubernetes (CKV_K8S_*)** — les plus courants sur cette plateforme :
```yaml
# securityContext durci (Pod/Container)
securityContext:
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities: { drop: ["ALL"] }
```
- Limites de ressources manquantes : ajouter `resources.requests` et `resources.limits` (cpu/mémoire).
- Image en `:latest` : épingler un tag précis.
- `hostNetwork/hostPID/privileged: true` : à retirer sauf besoin prouvé.

**Terraform cloud (CKV_AWS_* / AZURE / GCP)** :
- Stockage public (S3/bucket) : bloquer l'accès public (`block_public_acls`, ACL privée).
- Chiffrement désactivé : activer chiffrement at-rest (KMS) sur bucket/volume/base.
- Security group `0.0.0.0/0` : restreindre aux CIDR/ports nécessaires.
- IAM `Action: "*"` / `Resource: "*"` : lister explicitement les actions et ressources.
- Logs/audit désactivés : activer (CloudTrail, flow logs, access logging).

**Dockerfile (CKV_DOCKER_*)** : `USER` non-root manquant, `HEALTHCHECK` absent — voir aussi le playbook Hadolint.

### Faux positif ou exception assumée
Si la règle ne s'applique pas à ce contexte (ex. environnement de test éphémère), l'exception se documente dans le code :
```yaml
# checkov:skip=CKV_K8S_22: justification courte ici
```
— toujours avec justification, jamais en masse.

### Vérification locale
```bash
checkov --directory . --compact
# ou cibler un fichier
checkov -f k8s/deployment.yaml
```

### Notes
- Corriger la **définition dans le dépôt** (fichier versionné), pas la ressource live : sinon le prochain déploiement réintroduit le problème.
- Beaucoup de findings K8s se règlent en usine : un bloc `securityContext` type ajouté au template de déploiement corrige des dizaines d'occurrences.
