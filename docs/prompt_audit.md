PROMPT AUDIT D'IMPACT (à lancer AVANT toute modification de Application)

Prompt générique pour agent de code. C'est un audit en LECTURE SEULE. Tu ne modifies AUCUN fichier. Tu produis un rapport.
Objectif : garantir que l'ajout de champs à l'entité Application (rendre gitRepositoryUrl nullable + ajouter les relations services et databases) ne casse pas le code existant (scan, quality-gate, DefectDojo, SonarQube, pipeline).

Ta mission : recenser et analyser, sans rien changer
Parcours TOUT le backend et produis un rapport structuré couvrant les 6 points suivants. Pour chaque occurrence, donne : le fichier, la ligne, l'extrait de code, et le risque + la correction recommandée.
1. Usages de getGitRepositoryUrl()
Trouve TOUS les appels à application.getGitRepositoryUrl() (ou via un getter Lombok équivalent). Pour chacun, indique s'il suppose une valeur non-null (ex. .trim(), .isBlank(), .substring(), passage direct à une méthode sans garde). Ces appels risquent un NullPointerException quand gitRepositoryUrl sera null (nouvelles apps multi-services). Liste-les tous.
2. Appels au constructeur new Application(...)
L'entité Application a @AllArgsConstructor. Si on ajoute 2 champs (services, databases), la signature change. Trouve TOUS les new Application(...) avec arguments positionnels — ils casseront à la compilation. Signale-les. (Les new Application() sans argument ou via builder ne sont pas concernés.)
3. DTO, mappers et sérialisation JSON

Trouve les DTO/mappers (ApplicationDto, MapStruct, conversions manuelles, objectMapper.convertValue) qui référencent les champs de Application.
Identifie les risques de boucle de sérialisation si services/databases sont ajoutés (ex. Application → services → application → …). Vérifie quelles annotations @JsonIgnoreProperties / @JsonManagedReference / @JsonBackReference existent et lesquelles manqueront pour les nouvelles relations.

4. Requêtes JPQL / @Query / projections
Trouve les requêtes (@Query, Criteria, SELECT new ...Dto(...)) qui listent explicitement les champs de Application ou construisent un DTO par constructeur. L'ajout de champs peut casser ces projections. Liste-les.
5. Chargement LAZY hors transaction
Les nouvelles relations services/databases seront @OneToMany(fetch = LAZY). Trouve les endpoints/méthodes qui sérialisent une Application complète hors d'une transaction ouverte (@Transactional) — accéder à ces relations y lèverait LazyInitializationException. Signale les points à risque.
6. Repositories et méthodes dérivées
Liste les méthodes de ApplicationRepository (surtout findByIdAndCreatedBy, findByApplication_Id, etc.) utilisées par le module de scan, pour confirmer qu'aucune ne dépend de la non-nullité de gitRepositoryUrl ni du nombre de champs.
Format du rapport attendu
Pour chaque point, un tableau : Fichier | Ligne | Extrait | Risque | Correction recommandée.
Termine par une section « Ordre de correction sûr » : la séquence exacte des modifications à faire pour que rien ne casse (ex. « 1. rendre gitRepositoryUrl nullable, 2. ajouter des gardes null dans QualityGateService lignes X/Y, 3. remplacer les new Application(...) par builder, 4. ajouter les relations, 5. protéger la sérialisation »).
Contrainte
NE MODIFIE RIEN. C'est un audit. Je validerai le rapport avant d'autoriser les changements.