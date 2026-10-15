package com.backend.devsecopsplatform_backend.service.qualitygate;

import com.backend.devsecopsplatform_backend.service.qualitygate.dto.QualityGateStageDto;
import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@Builder
public class SecurityScoreInput {
    /** Findings DefectDojo (source unique pour pénalités de sévérité). */
    private Map<String, Integer> ddBySeverity;
    private int secrets;

    /**
     * Conteneur (Grype) : dimension distincte, à paliers absolus -- voir SecurityScoringService.
     * Non fondue dans ddBySeverity (soustraite en amont, comme le DAST -- voir
     * QualityGateService.buildBySeverity). containerCritical existait déjà mais n'était encore
     * jamais lu par computePostureScore() avant le 29/08/2026 (diagnostic score-à-0) ; les 3
     * autres sévérités sont nouvelles.
     */
    private int containerCritical;
    private int containerHigh;
    private int containerMedium;
    private int containerLow;

    /** Seuils CI (summary ingéré ou {@link QualityGateThresholds}). */
    private int containerCriticalThreshold;
    private int scaCriticalThreshold;

    private String sonarQgStatus;
    private String securityRating;
    private String reliabilityRating;
    private String maintainabilityRating;
    private double coverage;
    /** false si la métrique coverage est absente (évite −5 sur 0 par défaut). */
    private boolean coverageKnown;
    private int securityHotspots;

    private List<QualityGateStageDto> stages;
    private boolean sonarAvailable;
    private boolean defectDojoAvailable;
    private int sonarBlockers;
    private int ncloc;

    /** DAST (ZAP) : dimension distincte, non fondue dans ddBySeverity -- voir SecurityScoringService. */
    private boolean dastApplicable;
    private int dastCritical;
    private int dastHigh;
    private int dastMedium;

    /**
     * CVSS moyen / nombre de findings avec CVSS connu, par sévérité (clés en minuscules :
     * "critical"/"high"/"medium"/"low"). Repli sûr : absent ou vide -> pénalités inchangées
     * (comportement identique au calcul par compte brut d'aujourd'hui).
     */
    @Builder.Default
    private Map<String, Double> avgCvssBySeverity = Map.of();
    @Builder.Default
    private Map<String, Integer> cvssKnownCountBySeverity = Map.of();
}
