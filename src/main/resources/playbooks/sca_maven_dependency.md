## Playbook: Dépendance vulnérable (Java / Maven)

### Quand ça arrive
- ScanType SCA (maven, dependency scanning)
- Finding sur un artifact Maven (groupId:artifactId) ou sur un CVE lié à une lib.

### Étapes
1) Identifier la dépendance directe/transitive concernée.
2) Mettre à jour la version dans `pom.xml` (ou via BOM) vers une version corrigée.
3) Vérifier compilation + tests.
4) Relancer l’analyse depuis la plateforme.

### Commandes utiles
```bash
mvn -q -DskipTests=false test
mvn -q dependency:tree | grep -i "<artifactId>"
mvn -q versions:display-dependency-updates
```

### Notes
- Si transitive, mettre à jour le parent (starter) ou ajouter une contrainte `dependencyManagement`.
- Pour Spring Boot : privilégier la mise à jour de la version Boot (BOM) plutôt que forcer une version isolée.

