package com.backend.devsecopsplatform_backend.controller.application;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class DeploymentHistoryItem {

    private UUID environmentId;
    private String environmentName;
    private String gitBranch;

    private Long pipelineId;
    private String pipelineStatus;
    private String environmentStatus;

    private String shortSha;
    private String commitMessage;

    private LocalDateTime createdAt;
    private LocalDateTime finishedAt;
    private List<Map<String, Object>> jobs;

    private String triggeredByUsername;
}

