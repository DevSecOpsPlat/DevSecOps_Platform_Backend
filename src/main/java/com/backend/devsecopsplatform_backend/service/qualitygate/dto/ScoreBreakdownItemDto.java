package com.backend.devsecopsplatform_backend.service.qualitygate.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScoreBreakdownItemDto {
    private String id;
    /** BLOCKING_CAP | DEFECTDOJO | SONAR_QUALITY | INFO */
    private String category;
    private String label;
    /** Impact négatif sur le score (0 pour une ligne informative). */
    private int impact;
    /** Plafond appliqué (ex. 40 pour secrets), null si pénalité simple. */
    private Integer capScore;
    private String detail;
}
