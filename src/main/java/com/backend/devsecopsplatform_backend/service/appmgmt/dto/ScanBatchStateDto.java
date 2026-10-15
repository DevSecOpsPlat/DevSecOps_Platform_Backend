package com.backend.devsecopsplatform_backend.service.appmgmt.dto;

import com.backend.devsecopsplatform_backend.controller.appmgmt.SecurityPostureResponse;
import com.backend.devsecopsplatform_backend.entity.PipelineStatus;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatchStatus;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * État reconstruit d'un {@link com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatch}
 * à partir du lot + ses {@code PipelineExecution}.
 */
public record ScanBatchStateDto(
        UUID batchId,
        UUID managedApplicationId,
        ScanBatchStatus status,
        Long gitlabPipelineId,
        UUID triggeredByUserId,
        LocalDateTime createdAt,
        LocalDateTime finishedAt,
        String verdict,
        Integer securityScore,
        String grade,
        Map<String, Object> verdictPayload,
        /** Figé sur le lot à la création — pas {@code services.size()}. */
        int expectedServiceCount,
        int finishedServiceCount,
        List<ScanBatchServiceStateDto> services,
        /** Checklist app-level -- même calcul que {@code ManagedAppScanService.extractQualityGates}. */
        List<SecurityPostureResponse.QualityGateItem> qualityGates
) {
    public record ScanBatchServiceStateDto(
            UUID pipelineExecutionId,
            UUID serviceId,
            String serviceName,
            String serviceRole,
            String gitBranch,
            String commitSha,
            PipelineStatus status,
            boolean finished,
            Map<String, Object> qualityGateJson,
            /** Checklist des hard gates pour ce service -- même calcul que la vue Quality Gate d'un
             *  service unique (SecurityScoringService), pour que l'historique des scans n'ait plus
             *  besoin de réimplémenter sa propre dérivation côté frontend. */
            List<SecurityPostureResponse.QualityGateItem> qualityGates
    ) {}
}
