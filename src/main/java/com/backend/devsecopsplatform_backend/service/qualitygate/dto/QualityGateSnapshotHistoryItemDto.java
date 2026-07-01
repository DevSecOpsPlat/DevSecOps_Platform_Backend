package com.backend.devsecopsplatform_backend.service.qualitygate.dto;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.UUID;

/** Métadonnées d'un snapshot conservé en BDD (payload complet via GET /snapshots/{id}). */
@Data
@Builder
public class QualityGateSnapshotHistoryItemDto {
    private UUID snapshotId;
    private UUID environmentId;
    private String environmentName;
    private String branch;
    private Long gitlabPipelineId;
    private String pipelineId;
    private Instant evaluatedAt;
    private Instant createdAt;
    private String source;
    private String verdict;
}
