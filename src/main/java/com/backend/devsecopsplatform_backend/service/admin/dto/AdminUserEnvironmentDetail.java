package com.backend.devsecopsplatform_backend.service.admin.dto;

import java.time.LocalDateTime;
import java.util.UUID;

public record AdminUserEnvironmentDetail(
        UUID id,
        UUID applicationId,
        String applicationName,
        String environmentName,
        /** Namespace K8s réel — permet de réutiliser tel quel GET /api/admin/monitoring/namespaces/{namespace}
         * (AdminMonitoringService.getNamespaceDetail) depuis la page détail Environnement, sans nouvel appel K8s. */
        String namespace,
        String gitBranch,
        String status,
        String url,
        Integer ttlHours,
        LocalDateTime createdAt,
        LocalDateTime expiresAt,
        Long gitlabPipelineId,
        String pipelineStatus,
        LocalDateTime pipelineStartedAt,
        LocalDateTime pipelineFinishedAt
) {}
