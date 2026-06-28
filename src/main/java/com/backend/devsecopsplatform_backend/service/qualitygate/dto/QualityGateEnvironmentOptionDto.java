package com.backend.devsecopsplatform_backend.service.qualitygate.dto;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.UUID;

@Data
@Builder
public class QualityGateEnvironmentOptionDto {
    private UUID environmentId;
    private String environmentName;
    private String branch;
    private String status;
    private String pipelineId;
    private String pipelineStatus;
    private Instant evaluatedAt;
    private Instant snapshotSavedAt;
    private UUID snapshotId;
    private String snapshotSource;
    private String verdict;
    private boolean hasSnapshot;
}
