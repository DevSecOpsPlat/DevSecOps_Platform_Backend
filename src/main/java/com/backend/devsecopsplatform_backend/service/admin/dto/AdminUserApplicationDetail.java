package com.backend.devsecopsplatform_backend.service.admin.dto;

import java.time.LocalDateTime;
import java.util.UUID;

public record AdminUserApplicationDetail(
        UUID id,
        String name,
        String description,
        String gitRepositoryUrl,
        LocalDateTime createdAt,
        long linkedEnvironmentsCount,
        AdminPipelineCounts pipelineCounts
) {}
