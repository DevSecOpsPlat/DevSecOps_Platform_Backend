package com.backend.devsecopsplatform_backend.service.qualitygate.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class QualityGateResultDto {
    private UUID applicationId;
    private String branch;
    private String pipelineId;
    private UUID environmentId;
    private Instant evaluatedAt;
    private String pipelineStatus;
    private List<QualityGateStageDto> stages;
    private Map<String, Object> metrics;
    /** RECOMMENDED | WITH_WARNINGS | NOT_RECOMMENDED | INDETERMINE | UNKNOWN */
    private String verdict;
    private String summary;
    private List<String> detailedRecommendations;
    /** Explication structurée du verdict (violations bloquantes, alertes). */
    private List<String> verdictExplanation;
    /** Conseils pratiques numérotés pour l'équipe. */
    private List<String> practicalAdvice;
    /** Comment la note / le verdict est calculé. */
    private String scoringNote;
    private List<QualityGateToolMetricDto> toolMetrics;
    private Map<String, Object> thresholds;
    private String trendNote;
    private String source;
    private String pipelineWebUrl;
    /** Insight IA optionnel (Ollama / provider configuré). */
    private String aiInsight;

    /** Score posture 0–100 + note A–E + décomposition. */
    private SecurityScoreDto securityScore;
    /** Dimensions Software Quality SonarQube 10+. */
    private List<SoftwareQualityDimensionDto> softwareQuality;
    /** Comptes H/M/L globaux SQ (métriques software_quality_*_severity_issues). */
    private Map<String, Integer> softwareQualitySeverity;
    /** Disponibilité Sonar + branche effective. */
    private SonarAvailabilityDto sonarAvailability;
    /** Branches disponibles (union Sonar, DefectDojo, envs). */
    private List<String> availableBranches;
    /** Verdict brut du stage security-validation. */
    private String ciVerdict;
    /** CI | SCORE | MERGED */
    private String verdictSource;

    /** Identifiant du snapshot BDD quand la réponse vient de {@code quality_gate_snapshots}. */
    private UUID snapshotId;
    /** PIPELINE_SYNC | CI_INGEST | MANUAL */
    private String snapshotRecordSource;
    /** true si chargé depuis la table (données figées), pas depuis DefectDojo/Sonar live. */
    private Boolean fromSnapshot;

    /** Hard gates violés (secrets, critical DD, blocker Sonar, QG ERROR). */
    private List<HardGateViolationDto> hardGateViolations;
    /** Hard gates indéterminés (source indisponible). */
    private List<HardGateViolationDto> hardGateIndeterminate;
    /** Message synthétique des hard gates violés. */
    private String hardGateSummary;
    /** true si getDashboard2 a répondu ; false si exception ou null. */
    private Boolean defectDojoAvailable;
    /** Sources indisponibles empêchant une recommandation complète. */
    private List<String> indeterminateSources;
    /** Bandeau « Recommandation incomplète ». */
    private String incompleteRecommendationMessage;

    /** Lignes de code non commentées (SonarQube) — base du calcul densité. */
    private Integer ncloc;
    /** SONAR_LIVE | SUMMARY | PIPELINE_GATE | SNAPSHOT | UNKNOWN */
    private String nclocSource;
}
