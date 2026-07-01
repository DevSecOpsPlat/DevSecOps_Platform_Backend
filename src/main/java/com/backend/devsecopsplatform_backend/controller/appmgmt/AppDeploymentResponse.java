package com.backend.devsecopsplatform_backend.controller.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeploymentStatus;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Data
@Builder
public class AppDeploymentResponse {
    private UUID id;
    private String namespace;
    private AppDeploymentStatus status;
    private Long gitlabPipelineId;
    private Instant deployedAt;
    private Map<String, Object> servicesState;
    private Instant createdAt;
    private Instant updatedAt;
    /** Bases avec URL de connexion générée (mot de passe masqué), pour l'écran d'état. */
    private List<AppDatabaseResponse> databases;
}
