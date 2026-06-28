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
public class QualityGateStageDto {
    private String name;
    private String toolLabel;
    /** PASS | WARN | FAIL | SKIPPED */
    private String status;
    /** Libellé affiché : Réussi, ÉCHEC, Avertissement, Ignoré */
    private String statusLabel;
    private String message;
    private boolean blocking;
    private Map<String, Object> metrics;
    private Map<String, Object> details;
}
