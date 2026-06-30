package com.backend.devsecopsplatform_backend.service.qualitygate;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class HardGateInput {
    private int secrets;
    private int ddCritical;
    private int sonarCritical;
    private int sonarBlockers;
    private String sonarQgStatus;
    private boolean defectDojoAvailable;
    private boolean sonarAvailable;
    /** false tant que le job Gitleaks/secrets n'a pas terminé (success ou failed). */
    @Builder.Default
    private boolean secretsEvaluable = false;
}
