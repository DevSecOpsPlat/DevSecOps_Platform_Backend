package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class DefectDojoDeployRecommendation {

    /** RECOMMANDE | NON_RECOMMANDE | INCONNU */
    private String status;
    private boolean deployRecommended;
    private int criticalCount;
    private int highCount;
    private int criticalThreshold;
    private String reason;
    private String source;
}
