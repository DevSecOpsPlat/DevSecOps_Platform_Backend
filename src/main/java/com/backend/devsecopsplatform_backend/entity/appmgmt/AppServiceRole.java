package com.backend.devsecopsplatform_backend.entity.appmgmt;

/**
 * Rôle d'un service applicatif. Détermine la logique de dépendance (un BACKEND peut
 * consommer une base) et l'exposition externe (FRONTEND exposé via Ingress/NodePort).
 */
public enum AppServiceRole {
    FRONTEND,
    BACKEND,
    WORKER
}
