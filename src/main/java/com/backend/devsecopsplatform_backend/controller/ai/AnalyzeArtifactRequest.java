package com.backend.devsecopsplatform_backend.controller.ai;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Requête d'analyse d'un artefact de pipeline par l'IA.
 * Tu envoies le contenu brut de l'artifact (JSON, texte, etc.) et l'IA renvoie
 * les vulnérabilités détectées, où les trouver et comment les corriger.
 */
@Data
public class AnalyzeArtifactRequest {

    /**
     * Contenu de l'artifact (JSON string, log, rapport texte, etc.).
     * Peut provenir de n'importe quel outil : Trivy, SonarQube, OWASP, etc.
     */
    @NotBlank(message = "Le contenu de l'artifact est requis")
    private String artifactContent;

    /**
     * Optionnel : type ou source de l'artifact (ex: "trivy", "sonarqube", "dependency-check")
     * pour aider l'IA à mieux interpréter le format.
     */
    private String artifactSource;
}
