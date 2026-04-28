package com.backend.devsecopsplatform_backend.service.admin.dto;

import java.time.LocalDateTime;
import java.util.UUID;

public record AdminUserEnvironmentDetail(
        UUID id,
        UUID applicationId,
        String applicationName,
        String environmentName,
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
