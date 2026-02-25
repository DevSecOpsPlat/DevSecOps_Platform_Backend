package com.backend.devsecopsplatform_backend.controller.application;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
public class DeploymentHistoryItem {

    private UUID environmentId;
    private String environmentName;
    private String gitBranch;

    private Long pipelineId;
    private String pipelineStatus;

    private String shortSha;
    private String commitMessage;

    private LocalDateTime createdAt;
    private LocalDateTime finishedAt;

    private String triggeredByUsername;
}

