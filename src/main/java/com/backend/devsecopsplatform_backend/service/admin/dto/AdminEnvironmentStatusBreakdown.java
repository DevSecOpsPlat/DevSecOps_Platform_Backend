package com.backend.devsecopsplatform_backend.service.admin.dto;

/**
 * Nombre d'environnements éphémères par statut pour un utilisateur.
 */
public record AdminEnvironmentStatusBreakdown(
        long pending,
        long building,
        long running,
        long failed,
        long destroyed,
        long expired
) {
    public long total() {
        return pending + building + running + failed + destroyed + expired;
    }

    public static AdminEnvironmentStatusBreakdown empty() {
        return new AdminEnvironmentStatusBreakdown(0, 0, 0, 0, 0, 0);
    }
}
