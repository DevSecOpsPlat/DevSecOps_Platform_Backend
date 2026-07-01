package com.backend.devsecopsplatform_backend.service.qualitygate.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SoftwareQualityDimensionDto {
    /** SECURITY | RELIABILITY | MAINTAINABILITY */
    private String dimension;
    private int issues;
    /** Note A–E (convertie depuis rating Sonar 1–5). */
    private String rating;
    private int ratingValue;
    /**
     * High / Medium / Low depuis measures/component (métriques SQ dédiées Sonar 10+).
     * Absent si métriques indisponibles (Sonar &lt; 10) — pas de re-calcul issues/search ici.
     */
    private Map<String, Integer> bySeverity;
}
