package com.backend.devsecopsplatform_backend.entity.appmgmt;

/** Statut d'une exécution de déploiement d'application managée. */
public enum AppDeploymentStatus {
    PENDING,
    DEPLOYING,
    RUNNING,
    FAILED,
    STOPPED
}
