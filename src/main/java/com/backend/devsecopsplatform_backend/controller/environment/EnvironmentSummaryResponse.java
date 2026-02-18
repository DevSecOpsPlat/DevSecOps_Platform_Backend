package com.backend.devsecopsplatform_backend.controller.environment;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
public class EnvironmentSummaryResponse {

    private UUID id;
    private String environmentName;
    private String gitRepositoryUrl;
    private String gitBranch;
    private Integer ttlHours;
    private String status;
    private LocalDateTime createdAt;
    private LocalDateTime expiresAt;
    private Long latestPipelineId;
    private String latestPipelineStatus;
}
