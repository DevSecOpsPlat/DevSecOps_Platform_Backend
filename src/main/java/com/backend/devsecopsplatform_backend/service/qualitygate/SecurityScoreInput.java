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
    private int containerCritical;

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
}
