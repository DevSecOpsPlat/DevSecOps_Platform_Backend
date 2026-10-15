package com.backend.devsecopsplatform_backend.service.admin.dto;

import java.util.UUID;

/**
 * Résumé d'un service (AppService) appartenant à une application admin — utilisé pour afficher
 * la composition d'une {@code ManagedApplication} dans l'inventaire admin (cf. docs/audit-dashboard-admin.md §6).
 */
public record AdminAppServiceSummary(
        UUID id,
        String name,
        String role,
        String gitRepositoryUrl,
        String gitBranch
) {}
