package com.backend.devsecopsplatform_backend.service.qualitygate.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Violation ou indétermination d'un hard gate bloquant. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HardGateViolationDto {
    /** secrets | dd_critical | sonar_blocker | sonar_qg */
    private String id;
    private String label;
    private String message;
    /** VIOLATED | INDETERMINATE */
    private String status;
}
