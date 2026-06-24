package com.backend.devsecopsplatform_backend.service.defectdojo.dto;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
public class DefectDojoTimeSeriesPoint {

    /** Jour (yyyy-MM-dd) ou semaine (MM/dd/yyyy). */
    private String period;
    private Map<String, Integer> bySeverity;
}
