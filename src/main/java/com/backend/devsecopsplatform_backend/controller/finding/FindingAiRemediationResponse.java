package com.backend.devsecopsplatform_backend.controller.finding;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class FindingAiRemediationResponse {
    private String problemSummary;
    /** Cause racine du problème (pourquoi ça arrive). */
    private String rootCause;
    private String impact;
    /** Risque métier (impact business : données, dispo, conformité, image). */
    private String businessRisk;
    private String location;
    /** Comment reproduire/observer le problème si pertinent ("" sinon). */
    private String reproduction;
    @Builder.Default
    private List<String> remediationSteps = new ArrayList<>();
    private String suggestedPatch;
    /** Code vulnérable (extrait "avant"). */
    private String secureCodeBefore;
    /** Code corrigé (extrait "après"). */
    private String secureCodeAfter;
    private String fullFileRewrite;
    @Builder.Default
    private List<String> bestPractices = new ArrayList<>();
    /** Références officielles (CWE/CVE/OWASP/doc). */
    @Builder.Default
    private List<ReferenceItem> references = new ArrayList<>();
    @Builder.Default
    private List<String> verificationHints = new ArrayList<>();
    @Builder.Default
    private List<String> verificationCommands = new ArrayList<>();
    /** Confiance de l'IA : HIGH | MEDIUM | LOW. */
    private String confidence;
    private String rawModelOutput;
    private String codeContextSource;

    private String aiProviderUsed;
    private String aiModelUsed;
    private Boolean quotaFallbackUsed;
    private String aiModelTier;
}
