package com.backend.devsecopsplatform_backend.controller.environment;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class DeployRequest {

    @NotBlank(message = "L'URL du repository Git est obligatoire")
    private String gitRepositoryUrl;

    @NotBlank(message = "La branche est obligatoire")
    private String branch;

    /**
     * Durée de la session de test en heures
     */
    @Min(value = 1, message = "La durée doit être d'au moins 1 heure")
    private Integer sessionDurationHours = 4;

    /**
     * Token GitHub pour cloner le repo (stocké chiffré en BDD).
     * Optionnel si repo public.
     */
    private String githubToken;

    /**
     * Chemin vers le Dockerfile dans le repo (ex: ./Dockerfile ou docker/Dockerfile).
     * Passé au pipeline GitLab comme DOCKERFILE_PATH.
     */
    private String dockerfilePath = "./Dockerfile";
}
