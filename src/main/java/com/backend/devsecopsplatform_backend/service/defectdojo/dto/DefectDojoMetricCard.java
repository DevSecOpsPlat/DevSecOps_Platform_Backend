package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
public class DefectDojoMetricCard {

    /** open | closed | verified | risk_accepted | false_positive | out_of_scope | total | inactive */
    private String key;
    private String label;
    private int total;
    private Map<String, Integer> bySeverity;
}
