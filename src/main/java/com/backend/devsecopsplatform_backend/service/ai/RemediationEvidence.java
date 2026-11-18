package com.backend.devsecopsplatform_backend.service.ai;

/**
 * Preuves réellement disponibles pour un finding, connues du backend (et non déclarées par le modèle).
 * Elles servent à :
 * <ul>
 *   <li>borner le niveau de confiance et le statut « confirmé » des causes/localisations ;</li>
 *   <li>séparer les entrées de cache par application et par état observé (une analyse HSTS d'une
 *       application FastAPI ne doit pas resservir pour une application Spring Boot).</li>
 * </ul>
 *
 * @param dynamicFinding   finding DAST (ZAP) : constat sur une réponse HTTP, pas sur le code
 * @param repositoryCode   un fichier a réellement été lu dans le dépôt (GitHub/GitLab/Dockerfile)
 * @param manualSnippet    extrait collé par l'utilisateur
 * @param scannerLocation  le scanner fournit lui-même fichier + ligne (SAST, secrets…)
 * @param liveCheck        le contrôle HTTP de la plateforme a donné une réponse exploitable
 * @param applicationScope id de l'application (portée du cache)
 * @param fingerprint      empreinte des preuves (URL, en-têtes observés, fichier lu)
 * @param pipelineContextRelevant false quand un AUTRE service que celui du finding a répondu (DAST) :
 *                         le contexte pipeline du service du finding décrirait alors la mauvaise application
 */
public record RemediationEvidence(
        boolean dynamicFinding,
        boolean repositoryCode,
        boolean manualSnippet,
        boolean scannerLocation,
        boolean liveCheck,
        String applicationScope,
        String fingerprint,
        boolean pipelineContextRelevant
) {
    public static RemediationEvidence none() {
        return new RemediationEvidence(false, false, false, false, false, "", "", true);
    }

    /** Au moins un élément concret au-delà du texte générique du scanner. */
    public boolean hasConcreteEvidence() {
        return repositoryCode || manualSnippet || scannerLocation || liveCheck;
    }
}
