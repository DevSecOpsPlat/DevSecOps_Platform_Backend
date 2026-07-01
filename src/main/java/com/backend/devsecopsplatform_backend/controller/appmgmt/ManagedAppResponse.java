package com.backend.devsecopsplatform_backend.controller.appmgmt;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class ManagedAppResponse {
    private UUID id;
    private String name;
    private String slug;
    private String description;
    private String createdByUsername;
    private Instant createdAt;
    private Instant updatedAt;
    private List<AppServiceResponse> services;
    private List<AppDatabaseResponse> databases;
    /** Dernier déploiement (null si jamais déployée). */
    private AppDeploymentResponse lastDeployment;
    /** Avertissements non bloquants (ex. backend sans BD, collision de port). */
    private List<String> warnings;
}
