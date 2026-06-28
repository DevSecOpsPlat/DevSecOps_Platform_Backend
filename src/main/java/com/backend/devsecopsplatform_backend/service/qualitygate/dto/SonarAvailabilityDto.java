package com.backend.devsecopsplatform_backend.service.qualitygate.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SonarAvailabilityDto {
    private boolean available;
    private String projectKey;
    /** Branche demandée par l'utilisateur / l'environnement. */
    private String requestedBranch;
    /** Branche effectivement interrogée chez SonarQube. */
    private String resolvedBranch;
    private String message;
    private String dashboardUrl;
}
