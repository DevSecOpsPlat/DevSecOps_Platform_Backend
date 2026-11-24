package com.backend.devsecopsplatform_backend.service.remediation;

import com.backend.devsecopsplatform_backend.controller.finding.dto.FindingAiRemediationResponse;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RemediationEvidencePolicyTest {

    private static final String DAST_CTX = """
            Titre: Strict-Transport-Security Header Not Set
            Type d'analyse: DAST (OWASP ZAP)
            Règle ZAP (pluginid): 10035
            [SCANNER] URL testées par ZAP: https://back.envirotest.cloud/, https://back.envirotest.cloud/docs
            """;

    private static FindingAiRemediationResponse modelAnswer(String root, String loc, String confidence) {
        return FindingAiRemediationResponse.builder()
                .problemSummary("Le serveur FastAPI ne renvoie pas HSTS.")
                .rootCauseStatus(root)
                .locationStatus(loc)
                .confidence(confidence)
                .suggestedPatch("app.add_middleware(...)")
                .diagnosis(List.of(
                        FindingAiRemediationResponse.DiagnosisItem.builder().statement("En-tête absent").source("SCANNER").build(),
                        FindingAiRemediationResponse.DiagnosisItem.builder().statement("main.py n'a pas de middleware").source("REPOSITORY").build()))
                .verificationCommands(List.of("curl -sI https://localhost:8000 | grep -i strict-transport-security"))
                .build();
    }

    @Test
    void dastWithoutEvidenceCannotBeConfirmedNorHighConfidence() {
        RemediationEvidence ev = new RemediationEvidence(true, false, false, false, false, "app-1", "x", true);
        FindingAiRemediationResponse out = AiAnalysisService.applyEvidencePolicy(
                modelAnswer("CONFIRMED", "CONFIRMED", "HIGH"), ev, false, DAST_CTX);

        assertEquals("PROBABLE", out.getRootCauseStatus());
        assertEquals("PROBABLE", out.getLocationStatus());
        assertEquals("MEDIUM", out.getConfidence());
        assertEquals("HIGH", out.getModelConfidence());
        // Aucun fichier lu ni contexte pipeline : l'élément « dépôt » est une hypothèse.
        assertEquals("HYPOTHESIS", out.getDiagnosis().get(1).getSource());
        assertEquals("SCANNER", out.getDiagnosis().get(0).getSource());
        // La commande localhost est remplacée par une vérification sur l'URL réellement testée.
        assertEquals(1, out.getVerificationCommands().size());
        String cmd = out.getVerificationCommands().get(0);
        assertTrue(cmd.contains("https://back.envirotest.cloud/"), cmd);
        assertTrue(cmd.contains("strict-transport-security"), cmd);
        assertNotNull(out.getConfidenceReason());
    }

    @Test
    void codeReadAndScannerLocationAllowHighConfidence() {
        RemediationEvidence ev = new RemediationEvidence(false, true, false, true, false, "app-1", "x", true);
        FindingAiRemediationResponse out = AiAnalysisService.applyEvidencePolicy(
                modelAnswer("CONFIRMED", "CONFIRMED", "HIGH"), ev, true, "Titre: SQL injection\n");

        assertEquals("CONFIRMED", out.getRootCauseStatus());
        assertEquals("HIGH", out.getConfidence());
        assertEquals("REPOSITORY", out.getDiagnosis().get(1).getSource());
        // Hors DAST, les commandes ne sont pas réécrites.
        assertEquals("curl -sI https://localhost:8000 | grep -i strict-transport-security", out.getVerificationCommands().get(0));
    }

    @Test
    void undeterminedCauseAndLocationDropThePatch() {
        RemediationEvidence ev = new RemediationEvidence(true, false, false, false, true, "app-1", "x", true);
        FindingAiRemediationResponse out = AiAnalysisService.applyEvidencePolicy(
                modelAnswer("UNDETERMINED", "UNDETERMINED", "HIGH"), ev, false, DAST_CTX);

        assertEquals("LOW", out.getConfidence());
        assertEquals("", out.getSuggestedPatch());
    }

    @Test
    void staticTemplateWithoutEvidenceIsCappedToMedium() {
        FindingAiRemediationResponse template = FindingAiRemediationResponse.builder()
                .problemSummary("CORS trop large").confidence("HIGH").build();
        FindingAiRemediationResponse out = AiAnalysisService.applyEvidencePolicy(
                template, RemediationEvidence.none(), false, "Titre: CORS\n");
        assertEquals("MEDIUM", out.getConfidence());
    }

    private static final String CSP_CTX = """
            Titre: Content Security Policy (CSP) Header Not Set
            Type d'analyse: DAST (OWASP ZAP)
            Règle ZAP (pluginid): 10038
            [SCANNER] URL testées par ZAP: https://aoo-1.envirotest.cloud/
            """;

    @Test
    void genericCodeReviewInEnglishIsRejected() {
        // Réponse réelle du modèle de secours qwen2.5-coder:1.5b sur le finding CSP (18/11/2026).
        FindingAiRemediationResponse r = FindingAiRemediationResponse.builder()
                .problemSummary("The provided code snippet is a Python FastAPI application that interacts with a PostgreSQL database "
                        + "to manage Docker configuration files. It includes routes for creating, listing, and updating configurations.")
                .rootCause("No specific root cause was identified based on the provided information.")
                .remediationSteps(List.of("Ensure that all dependencies are installed correctly using pip or poetry."))
                .build();
        RemediationEvidence ev = new RemediationEvidence(true, true, false, false, false, "app", "x", true);
        assertNotNull(AiAnalysisService.qualityProblem(r, CSP_CTX, ev));
    }

    @Test
    void offTopicFrenchAnswerIsRejectedButARelevantOneIsKept() {
        RemediationEvidence ev = new RemediationEvidence(true, true, false, false, false, "app", "x", true);
        FindingAiRemediationResponse offTopic = FindingAiRemediationResponse.builder()
                .problemSummary("Le code est bien structuré et suit les bonnes pratiques Python.")
                .remediationSteps(List.of("Installer les dépendances avec pip."))
                .build();
        assertEquals("réponse sans rapport avec le finding", AiAnalysisService.qualityProblem(offTopic, CSP_CTX, ev));

        FindingAiRemediationResponse relevant = FindingAiRemediationResponse.builder()
                .problemSummary("La page d'accueil servie par le service front ne renvoie pas d'en-tête Content‑Security‑Policy.")
                .remediationSteps(List.of("Définir une CSP adaptée aux ressources chargées, d'abord en Report-Only."))
                .build();
        assertNull(AiAnalysisService.qualityProblem(relevant, CSP_CTX, ev));
    }

    @Test
    void proseIsNotAPatch() {
        assertFalse(AiAnalysisService.looksLikeCode(
                "The suggested patch would be to install all dependencies using pip or poetry and configure the proxy."));
        assertTrue(AiAnalysisService.looksLikeCode("add_header Content-Security-Policy \"default-src 'self'\" always;"));
    }

    @Test
    void stepsReturnedAsObjectsAreRead() throws Exception {
        com.fasterxml.jackson.databind.JsonNode arr = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree("[{\"step\":\"1. Ouvrir vite.config.ts\"},\"2) Ajouter server.headers\",{\"n\":3}]");
        assertEquals(List.of("Ouvrir vite.config.ts", "Ajouter server.headers"), AiAnalysisService.readTextItems(arr));
    }

    @Test
    void groqDurationsAreParsed() {
        assertEquals(5692, AiAnalysisService.parseGroqDuration("5.692s"));
        assertEquals(86400, AiAnalysisService.parseGroqDuration("1m26.4s"));
        assertEquals(450, AiAnalysisService.parseGroqDuration("450ms"));
        assertEquals(-1, AiAnalysisService.parseGroqDuration("bientôt"));
    }

    @Test
    void cacheKeyIsScopedByApplicationAndEvidence() {
        AiRemediationCacheService cache = new AiRemediationCacheService(null, null);
        String rule = "cwe-319|strict-transport-security header not set";
        String a = cache.computeCacheKey(rule, "", null, "", false,
                new RemediationEvidence(true, false, false, false, true, "app-a", "f1", true));
        String b = cache.computeCacheKey(rule, "", null, "", false,
                new RemediationEvidence(true, false, false, false, true, "app-b", "f1", true));
        String c = cache.computeCacheKey(rule, "", null, "", false,
                new RemediationEvidence(true, false, false, false, true, "app-a", "f2", true));
        assertNotEquals(a, b);
        assertNotEquals(a, c);
        assertEquals(a, cache.computeCacheKey(rule, "", null, "", false,
                new RemediationEvidence(true, false, false, false, true, "app-a", "f1", true)));
    }
}
