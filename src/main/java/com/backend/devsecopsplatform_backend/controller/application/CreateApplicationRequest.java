package com.backend.devsecopsplatform_backend.controller.application;


import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class CreateApplicationRequest {

    @NotBlank(message = "Le nom est obligatoire")
    private String name;

    private String description;

    @NotBlank(message = "L'URL du repository Git est obligatoire")
    @Pattern(regexp = "^https://github\\.com/.+/.+$",
            message = "URL GitHub invalide (format: https://github.com/user/repo)")
    private String gitRepositoryUrl;

    @Pattern(regexp = "^\\./.*$",
            message = "Le chemin du Dockerfile doit commencer par ./ (ex: ./Dockerfile)")
    private String dockerfilePath = "./Dockerfile";

    /**
     * Token GitHub pour accéder au repository privé
     * Format: ghp_xxxxxxxxxxxxxxxxxxxx
     */
    @NotBlank(message = "Le token GitHub est obligatoire pour les repos privés")
    @Pattern(regexp = "^(ghp_|gho_|github_pat_).+$",
            message = "Token GitHub invalide (doit commencer par ghp_, gho_ ou github_pat_)")
    private String githubToken;
}