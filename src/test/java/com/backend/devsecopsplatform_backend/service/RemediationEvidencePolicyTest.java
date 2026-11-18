package com.backend.devsecopsplatform_backend.service;

import com.backend.devsecopsplatform_backend.controller.finding.FindingAiRemediationResponse;
import com.backend.devsecopsplatform_backend.service.ai.AiRemediationCacheService;
import com.backend.devsecopsplatform_backend.service.ai.RemediationEvidence;
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
        RemediationEvidence ev = new RemediationEvidence(true, false, false, false, false, "app-1", "x");
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
        RemediationEvidence ev = new RemediationEvidence(false, true, false, true, false, "app-1", "x");
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
        RemediationEvidence ev = new RemediationEvidence(true, false, false, false, true, "app-1", "x");
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

    @Test
    void cacheKeyIsScopedByApplicationAndEvidence() {
        AiRemediationCacheService cache = new AiRemediationCacheService(null, null);
        String rule = "cwe-319|strict-transport-security header not set";
        String a = cache.computeCacheKey(rule, "", null, "", false,
                new RemediationEvidence(true, false, false, false, true, "app-a", "f1"));
        String b = cache.computeCacheKey(rule, "", null, "", false,
                new RemediationEvidence(true, false, false, false, true, "app-b", "f1"));
        String c = cache.computeCacheKey(rule, "", null, "", false,
                new RemediationEvidence(true, false, false, false, true, "app-a", "f2"));
        assertNotEquals(a, b);
        assertNotEquals(a, c);
        assertEquals(a, cache.computeCacheKey(rule, "", null, "", false,
                new RemediationEvidence(true, false, false, false, true, "app-a", "f1")));
    }
}
