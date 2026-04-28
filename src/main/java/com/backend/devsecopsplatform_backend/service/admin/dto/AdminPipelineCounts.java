package com.backend.devsecopsplatform_backend.service.admin.dto;

/**
 * Agrégat du nombre de pipelines par résultat pour un périmètre (utilisateur ou application).
 */
public record AdminPipelineCounts(
        long success,
        long failed,
        long running,
        long pending,
        long canceled,
        long skipped
) {
    public long total() {
        return success + failed + running + pending + canceled + skipped;
    }

    public static AdminPipelineCounts empty() {
        return new AdminPipelineCounts(0, 0, 0, 0, 0, 0);
    }
}
