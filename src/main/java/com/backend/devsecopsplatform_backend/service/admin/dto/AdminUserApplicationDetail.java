package com.backend.devsecopsplatform_backend.service.admin.dto;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Une ligne "Application" de l'inventaire admin. Représente soit une {@code ManagedApplication}
 * réelle (multi-services, {@code standalone = false}), soit un {@code AppService} autonome, sans
 * application parente (projet mono-service historique, {@code standalone = true}) — cf.
 * docs/audit-dashboard-admin.md §0 pour le détail des deux modèles.
 */
public record AdminUserApplicationDetail(
        UUID id,
        String name,
        String description,
        String gitRepositoryUrl,
        LocalDateTime createdAt,
        long linkedEnvironmentsCount,
        AdminPipelineCounts pipelineCounts,
        boolean standalone,
        List<AdminAppServiceSummary> services,
        long databasesCount
) {}
