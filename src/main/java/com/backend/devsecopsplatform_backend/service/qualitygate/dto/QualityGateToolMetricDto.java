package com.backend.devsecopsplatform_backend.service.qualitygate.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class QualityGateToolMetricDto {
    private String id;
    private String label;
    private String type;
    private int critical;
    private int high;
    private int medium;
    private int low;
    private int total;
    private String source;
    private Map<String, Object> raw;
    /** Statut du stage pipeline associé (PASS | WARN | FAIL | SKIPPED). */
    private String stageStatus;
    private String stageName;
    private String stageLabel;
}
