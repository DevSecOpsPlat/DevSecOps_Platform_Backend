package com.backend.devsecopsplatform_backend.controller.ai;

import lombok.Data;

/**
 * Assistant pipeline : question libre + contexte (projet, URLs, stages, logs optionnels).
 */
@Data
public class ExplainPipelineLogsRequest {

    /**
     * Logs du job sélectionné (optionnel — utile pour debug, pas obligatoire
     * pour des questions du type « quelle est l'URL ? »).
     */
    private String logs;

    /** Nom du job GitLab (ex: deploy:trigger-backend). */
    private String jobName;

    /** Stage CI (ex: deploy-k8s). */
    private String stageName;

    /** Statut du job (failed, success, …). */
    private String jobStatus;

    /** SCAN | DEPLOY. */
    private String pipelineKind;

    /** Vue synthétique des stages (ex: "setup=success; build=success; deploy-k8s=failed"). */
    private String stagesOverview;

    /** Type / stack projet (ex: react, spring, docker-compose). */
    private String projectHint;

    /**
     * Contexte riche du projet / déploiement : namespace, URLs services,
     * statut déploiement, pipelineId, noms des services, etc.
     */
    private String projectContext;

    /**
     * Question libre (ex: "c'est quoi l'URL du front ?", "explique ce log").
     * Si vide → explication standard des logs / état pipeline.
     */
    private String userQuestion;
}
