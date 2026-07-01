package com.backend.devsecopsplatform_backend.controller.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class AppServiceResponse {
    private UUID id;
    private String name;
    private AppServiceRole role;
    private String gitRepositoryUrl;
    /** Le token n'est jamais renvoyé ; seul un booléen indique sa présence. */
    private boolean hasGitToken;
    private String gitBranch;
    private String dockerfilePath;
    private String buildContext;
    private Integer exposedPort;
    private UUID dependsOnServiceId;
    private UUID dependsOnDatabaseId;
    private String dbUrlEnvVar;
    private Integer replicas;
    private String healthCheckPath;
    private String cpuRequest;
    private String cpuLimit;
    private String memoryRequest;
    private String memoryLimit;
    private List<EnvVarResponse> envVars;
    private Instant createdAt;
    private Instant updatedAt;
}
