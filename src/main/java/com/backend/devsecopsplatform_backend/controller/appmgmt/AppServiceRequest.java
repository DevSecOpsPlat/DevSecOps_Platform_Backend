package com.backend.devsecopsplatform_backend.controller.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/** Création / modification d'un service applicatif. */
@Data
public class AppServiceRequest {

    @NotBlank(message = "Le nom du service est obligatoire")
    private String name;

    @NotNull(message = "Le rôle du service est obligatoire")
    private AppServiceRole role;

    @NotBlank(message = "L'URL du repository Git est obligatoire")
    private String gitRepositoryUrl;

    /**
     * Token Git en clair (chiffré au repos). Optionnel en modification : si null/vide,
     * l'ancien token est conservé.
     */
    private String gitToken;

    private String gitBranch = "main";

    private String dockerfilePath = "Dockerfile";

    private String buildContext = ".";

    @NotNull(message = "Le port exposé est obligatoire")
    @Min(1)
    private Integer exposedPort;

    private UUID dependsOnServiceId;

    private UUID dependsOnDatabaseId;

    private String dbUrlEnvVar = "DATABASE_URL";

    @Min(1)
    private Integer replicas = 1;

    private String healthCheckPath;

    private String cpuRequest;
    private String cpuLimit;
    private String memoryRequest;
    private String memoryLimit;

    private List<EnvVarRequest> envVars = new ArrayList<>();
}
