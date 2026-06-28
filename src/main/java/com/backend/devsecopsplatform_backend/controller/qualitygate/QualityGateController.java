package com.backend.devsecopsplatform_backend.controller.qualitygate;

import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.service.finding.FindingIngestionService;
import com.backend.devsecopsplatform_backend.service.qualitygate.QualityGateService;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.QualityGateEnvironmentOptionDto;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.QualityGateResultDto;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.QualityGateSnapshotHistoryItemDto;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.SecurityGateIngestRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/quality-gate")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local", "http://envirotest.local:4200"})
public class QualityGateController {

    private final QualityGateService qualityGateService;
    private final FindingIngestionService findingIngestionService;
    private final PipelineExecutionRepository pipelineExecutionRepository;

    @Value("${pipeline.secret}")
    private String pipelineSecret;

    /** Ingestion du verdict CI (job security-validation). */
    @PostMapping("/ingest")
    public ResponseEntity<Map<String, String>> ingest(@RequestBody SecurityGateIngestRequest request) {
        qualityGateService.ingestFromPipeline(request);
        return ResponseEntity.ok(Map.of("status", "ok"));
    }

    @GetMapping
    public ResponseEntity<?> get(
            @RequestParam UUID applicationId,
            @RequestParam(required = false) String branch,
            @RequestParam(required = false) UUID environmentId,
            @RequestParam(required = false) UUID snapshotId,
            @RequestParam(required = false, defaultValue = "false") boolean refresh
    ) {
        try {
            return ResponseEntity.ok(qualityGateService.getForApplication(
                    applicationId, branch, environmentId, refresh, snapshotId));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            org.slf4j.LoggerFactory.getLogger(QualityGateController.class)
                    .error("Quality gate error for app {} branch {}", applicationId, branch, e);
            return ResponseEntity.internalServerError().body(Map.of(
                    "message", "Impossible de charger le quality gate",
                    "detail", e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()
            ));
        }
    }

    @PostMapping("/ai-insight")
    public ResponseEntity<Map<String, String>> aiInsight(
            @RequestParam UUID applicationId,
            @RequestParam(required = false) String branch
    ) {
        String insight = qualityGateService.generateAiInsight(applicationId, branch);
        if (insight == null || insight.isBlank()) {
            return ResponseEntity.ok(Map.of(
                    "insight", "",
                    "message", "IA non disponible (vérifiez ai.enabled et le provider Ollama/Groq)"
            ));
        }
        return ResponseEntity.ok(Map.of("insight", insight));
    }

    @PostMapping("/snapshots/refresh")
    public ResponseEntity<?> refreshSnapshot(
            @RequestParam UUID applicationId,
            @RequestParam UUID environmentId
    ) {
        return captureSnapshot(applicationId, environmentId);
    }

    /** Capture le snapshot via API (sans webhook) : ingestion artifacts + écriture BDD. */
    @PostMapping("/snapshots/capture")
    public ResponseEntity<?> captureSnapshot(
            @RequestParam UUID applicationId,
            @RequestParam UUID environmentId
    ) {
        try {
            var executionOpt = pipelineExecutionRepository
                    .findByEnvironmentIdAndApplicationId(environmentId, applicationId);
            if (executionOpt.isPresent() && executionOpt.get().getGitlabPipelineId() != null) {
                try {
                    findingIngestionService.ingestFromAggregateArtifacts(
                            executionOpt.get().getGitlabPipelineId());
                } catch (Exception e) {
                    log.warn("Ingestion artifacts échouée (capture env {}): {}", environmentId, e.getMessage());
                }
            }
            return ResponseEntity.ok(qualityGateService.captureSnapshotViaApi(applicationId, environmentId));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            log.error("Capture snapshot échouée app {} env {}", applicationId, environmentId, e);
            return ResponseEntity.internalServerError().body(Map.of(
                    "message", "Capture du snapshot impossible",
                    "detail", e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()
            ));
        }
    }

    /** Appelé par le pipeline GitLab à la fin — pas de JWT, secret partagé ({@code X-Pipeline-Secret}). */
    @PostMapping("/internal/snapshot")
    public ResponseEntity<?> pipelineSnapshot(
            @RequestParam UUID environmentId,
            @RequestHeader("X-Pipeline-Secret") String secret
    ) {
        if (pipelineSecret == null || pipelineSecret.isBlank() || !pipelineSecret.equals(secret)) {
            return ResponseEntity.status(403).body(Map.of("message", "Secret invalide"));
        }
        try {
            pipelineExecutionRepository.findByEnvironmentIdWithDetails(environmentId)
                    .ifPresent(execution -> {
                        if (execution.getGitlabPipelineId() != null) {
                            try {
                                findingIngestionService.ingestFromAggregateArtifacts(
                                        execution.getGitlabPipelineId());
                            } catch (Exception e) {
                                log.warn("Ingestion artifacts échouée (pipeline internal env {}): {}",
                                        environmentId, e.getMessage());
                            }
                        }
                    });

            QualityGateResultDto result = qualityGateService.captureSnapshotFromPipeline(environmentId);
            return ResponseEntity.ok(Map.of("status", "ok", "verdict", result.getVerdict()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            log.error("Pipeline snapshot failed env {}", environmentId, e);
            return ResponseEntity.internalServerError().body(Map.of("message", e.getMessage()));
        }
    }

    @GetMapping("/branches")
    public ResponseEntity<List<String>> branches(@RequestParam UUID applicationId) {
        return ResponseEntity.ok(qualityGateService.listBranches(applicationId));
    }

    @PostMapping("/snapshots/backfill")
    public ResponseEntity<Map<String, Object>> backfillSnapshots(@RequestParam UUID applicationId) {
        int created = qualityGateService.backfillMissingSnapshots(applicationId);
        return ResponseEntity.ok(Map.of("status", "ok", "created", created));
    }

    @GetMapping("/snapshots/history")
    public ResponseEntity<List<QualityGateSnapshotHistoryItemDto>> snapshotHistory(
            @RequestParam UUID applicationId,
            @RequestParam(required = false) String branch,
            @RequestParam(required = false) UUID environmentId
    ) {
        return ResponseEntity.ok(qualityGateService.listSnapshotHistory(applicationId, branch, environmentId));
    }

    @GetMapping("/snapshots/{snapshotId}")
    public ResponseEntity<?> getSnapshot(
            @RequestParam UUID applicationId,
            @PathVariable UUID snapshotId
    ) {
        try {
            return ResponseEntity.ok(qualityGateService.getSnapshotById(applicationId, snapshotId));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @GetMapping("/environments")
    public ResponseEntity<List<QualityGateEnvironmentOptionDto>> environments(
            @RequestParam UUID applicationId,
            @RequestParam(required = false) String branch
    ) {
        return ResponseEntity.ok(qualityGateService.listEnvironments(applicationId, branch));
    }
}
