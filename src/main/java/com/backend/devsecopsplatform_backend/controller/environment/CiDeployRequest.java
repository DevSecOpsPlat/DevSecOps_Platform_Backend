package com.backend.devsecopsplatform_backend.controller.environment;

import lombok.Data;

import java.util.Map;

@Data
public class CiDeployRequest {
    /** Image unique historique (compatibilité mono-service). */
    private String image;
    /** Images complètes indexées par nom logique/K8s du service. */
    private Map<String, String> images;
    private String namespace;
    private String deploymentId;
    private String environmentId;
    /** Nom logique ou K8s du service buildé par ce job CI (optionnel). */
    private String serviceName;
}
