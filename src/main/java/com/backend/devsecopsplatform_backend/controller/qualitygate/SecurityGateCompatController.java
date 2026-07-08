package com.backend.devsecopsplatform_backend.controller.qualitygate;

import com.backend.devsecopsplatform_backend.service.PipelineStageSyncService;
import com.backend.devsecopsplatform_backend.service.finding.FindingIngestionService;
import com.backend.devsecopsplatform_backend.service.qualitygate.QualityGateService;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.SecurityGateIngestRequest;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Compatibilité avec le job CI security-validation (POST /api/security-gate).
 * Authentification via {@code X-Pipeline-Secret} (pas de JWT).
 *
 * <p>Ne dépend pas du webhook GitLab : à la fin du job CI, on synchronise les stages
 * via l'API GitLab et on ingère les findings (même rôle que le webhook pipeline).</p>
 */
@RestController
@RequestMapping("/api/security-gate")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local", "http://envirotest.local:4200"})
public class SecurityGateCompatController {

    private final QualityGateService qualityGateService;
    private final PipelineStageSyncService pipelineStageSyncService;
    private final FindingIngestionService findingIngestionService;

    @Value("${pipeline.secret}")
    private String pipelineSecret;

    @PostMapping
    public ResponseEntity<?> ingest(
            @RequestBody SecurityGateIngestRequest request,
            @RequestHeader(value = "X-Pipeline-Secret", required = false) String secret
    ) {
        if (pipelineSecret == null || pipelineSecret.isBlank() || !pipelineSecret.equals(secret)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Secret pipeline invalide ou manquant (header X-Pipeline-Secret)."));
        }
        try {
            log.info("security-gate ingest kind={} app={} env={} deployment={} pipeline_id={}",
                    request.getKind(), request.getApplicationId(), request.getEnvironmentId(),
                    request.getDeploymentId(), request.getPipelineId());
            Long gitlabPipelineId = resolveGitlabPipelineId(request);
            if (gitlabPipelineId != null && gitlabPipelineId > 0) {
                var ensured = request.isDeployKind()
                        ? qualityGateService.ensureDeployPipelineExecution(
                                request.getApplicationId(), gitlabPipelineId, request)
                        : (request.getApplicationId() != null
                                ? qualityGateService.ensureScanPipelineExecution(
                                        request.getApplicationId(), gitlabPipelineId, request)
                                : null);
                log.info("pipeline_executions assuré pour GitLab #{} → exec {}",
                        gitlabPipelineId, ensured != null ? ensured.getId() : null);
            }
            qualityGateService.ingestFromPipeline(request);
            schedulePostIngestSync(request, gitlabPipelineId, request.getApplicationId());
            return ResponseEntity.ok(Map.of("status", "ok"));
        } catch (IllegalArgumentException e) {
            log.warn("security-gate ingest refusé: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    private void schedulePostIngestSync(
            SecurityGateIngestRequest request,
            Long gitlabPipelineId,
            UUID applicationId
    ) {
        if (gitlabPipelineId == null || gitlabPipelineId <= 0) {
            return;
        }
        try {
            qualityGateService.captureSnapshotAfterCiIngest(gitlabPipelineId, applicationId);
        } catch (Exception e) {
            log.warn("Snapshot QG après security-gate (#{}): {}", gitlabPipelineId, e.getMessage());
        }
        try {
            pipelineStageSyncService.syncStagesForPipeline(gitlabPipelineId);
        } catch (Exception e) {
            log.warn("Sync stages GitLab après security-gate (#{}): {}", gitlabPipelineId, e.getMessage());
        }
        CompletableFuture.runAsync(() -> {
            try {
                findingIngestionService.ingestFromAggregateArtifacts(gitlabPipelineId);
            } catch (Exception e) {
                log.warn("Ingestion findings après security-gate (#{}): {}", gitlabPipelineId, e.getMessage());
            }
        });
    }

    private Long resolveGitlabPipelineId(SecurityGateIngestRequest request) {
        String raw = request.getPipelineId();
        if ((raw == null || raw.isBlank()) && request.getSummary() != null && !request.getSummary().isNull()) {
            JsonNode node = request.getSummary().get("pipeline_id");
            if (node != null && !node.isNull()) {
                raw = node.asText();
            }
        }
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Long.parseLong(raw.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
