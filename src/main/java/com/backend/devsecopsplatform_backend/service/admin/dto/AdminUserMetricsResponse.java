package com.backend.devsecopsplatform_backend.service.admin.dto;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * DTO utilisé par le dashboard admin : profil, métriques agrégées, applications et environnements détaillés.
 */
public record AdminUserMetricsResponse(
        UUID id,
        String username,
        String email,
        List<String> roles,
        String accountStatus,
        LocalDateTime createdAt,
        LocalDateTime updatedAt,
        LocalDateTime validatedAt,
        String validatedByUsername,
        String rejectionReason,
        long activeEnvironmentsCount,
        long pipelinesCount,
        long applicationsCount,
        AdminPipelineCounts pipelineCounts,
        AdminEnvironmentStatusBreakdown environmentStatusBreakdown,
        List<AdminUserApplicationDetail> applications,
        List<AdminUserEnvironmentDetail> environments
) {}
