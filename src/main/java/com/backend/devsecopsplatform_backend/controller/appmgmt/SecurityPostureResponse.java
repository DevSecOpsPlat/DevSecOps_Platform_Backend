package com.backend.devsecopsplatform_backend.controller.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatchStatus;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Verdict courant d'une application = dernier {@link ScanBatchStatus#COMPLETE},
 * plus services dont le commit scanné ≠ HEAD actuel.
 * Option A : compteurs DefectDojo agrégés + top findings bloquants (drill-down hub service).
 */
@Data
@Builder
public class SecurityPostureResponse {

    private UUID managedApplicationId;
    private boolean hasCompleteBatch;
    /** PENDING | RUNNING | PARTIAL | COMPLETE | FAILED — statut du lot exposé. */
    private String batchStatus;
    private UUID batchId;
    private LocalDateTime batchFinishedAt;
    private LocalDateTime batchCreatedAt;
    private String verdict;
    private Integer securityScore;
    private String grade;
    private Long gitlabPipelineId;
    private int expectedServiceCount;
    private int finishedServiceCount;
    /** true si au moins un service a un HEAD différent du commit scanné. */
    private boolean obsolete;
    private List<ObsoleteService> obsoleteServices;
    private String message;

    /** Compteurs open DefectDojo agrégés sur les services du lot (figés). */
    private Map<String, Integer> bySeverity;
    /** Findings Critical/High cliquables → hub service. */
    private List<TopBlockingFinding> topBlockingFindings;
    /** Service dont le score réel a dimensionné le score app. */
    private DimensioningService dimensioningService;
    private List<ServiceSummary> services;
    /** Quality gates / hard gates expliqués (app + agrégat services). */
    private List<QualityGateItem> qualityGates;

    @Data
    @Builder
    public static class ObsoleteService {
        private UUID serviceId;
        private String serviceName;
        private String gitBranch;
        private String scannedCommitSha;
        private String headCommitSha;
    }

    @Data
    @Builder
    public static class TopBlockingFinding {
        private Integer findingId;
        private String title;
        private String severity;
        private UUID serviceId;
        private String serviceName;
        private String scanType;
        private String filePath;
        private String cve;
    }

    @Data
    @Builder
    public static class DimensioningService {
        private UUID serviceId;
        private String serviceName;
        private String serviceRole;
        private Boolean publiclyExposed;
        private Integer securityScore;
        private String grade;
        private Integer adjustedScoreForSelection;
    }

    @Data
    @Builder
    public static class ServiceSummary {
        private UUID serviceId;
        private String serviceName;
        private String serviceRole;
        private String verdict;
        private Integer securityScore;
        private String grade;
        private Map<String, Integer> bySeverity;
        private Boolean hardGateViolated;
        private Boolean indeterminate;
        private List<String> hardGateIds;
        private List<String> indeterminateSources;
    }

    @Data
    @Builder
    public static class QualityGateItem {
        /** secrets | dd_critical | sonar_blocker | sonar_qg | … */
        private String id;
        private String label;
        /** PASS | FAIL | UNKNOWN */
        private String status;
        private String message;
        private String scope;
    }
}
