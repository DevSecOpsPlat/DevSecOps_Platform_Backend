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
    /** Confiance finale : HIGH | MEDIUM | LOW, bornée par les preuves réellement disponibles (backend). */
    private String confidence;
    /** Pourquoi ce niveau de confiance (preuves présentes / manquantes), rédigé par le backend. */
    private String confidenceReason;
    /** Confiance déclarée par le modèle, avant bornage (transparence). */
    private String modelConfidence;

    // ── Format v2 (diagnostic sourcé) — absents des analyses antérieures et des modèles statiques ──

    /** Éléments du diagnostic, chacun avec sa provenance. */
    @Builder.Default
    private List<DiagnosisItem> diagnosis = new ArrayList<>();
    /** CONFIRMED | PROBABLE | UNDETERMINED */
    private String rootCauseStatus;
    /** CONFIRMED | PROBABLE | UNDETERMINED */
    private String locationStatus;
    /** Niveaux où la correction peut s'appliquer (application, reverse proxy, CDN…). */
    @Builder.Default
    private List<FixLayer> fixLayers = new ArrayList<>();
    /** Langage du correctif pour la coloration (python, java, yaml, nginx, http, bash…). */
    private String patchLanguage;
    /** Fichier ou composant auquel s'applique le correctif. */
    private String patchTarget;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DiagnosisItem {
        private String statement;
        /** SCANNER | PLATFORM_CHECK | REPOSITORY | HYPOTHESIS */
        private String source;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class FixLayer {
        /** APPLICATION | REVERSE_PROXY | CDN_TLS | KUBERNETES | WEB_SERVER | BUILD | DEPENDENCY | OTHER */
        private String layer;
        private String description;
        private boolean recommended;
    }
    private String rawModelOutput;
    private String codeContextSource;

    private String aiProviderUsed;
    private String aiModelUsed;
    private Boolean quotaFallbackUsed;
    private String aiModelTier;
    /** CACHE | STATIC | GROQ | OPENROUTER | OLLAMA */
    private String responseSource;
    /** PENDING | COMPLETE | FAILED — présent si analyse Ollama asynchrone */
    private String status;
    /** Identifiant de job pour polling si status=PENDING */
    private String jobId;
}
