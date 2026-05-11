package com.backend.devsecopsplatform_backend.controller.pipeline;

import com.backend.devsecopsplatform_backend.controller.environment.PipelineScanResponse;
import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.service.GitLabService;
import com.backend.devsecopsplatform_backend.service.PipelineStageSyncService;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/pipelines")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:4200","http://envirotest.local", "http://envirotest.local:4200"})
public class PipelineController {

    private final EphemeralEnvironmentRepository environmentRepository;
    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final UserRepository userRepository;
    private final GitLabService gitLabService;
    private final PipelineStageSyncService pipelineStageSyncService;

    private com.backend.devsecopsplatform_backend.entity.User getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getName() == null) {
            throw new RuntimeException("Utilisateur non authentifié");
        }
        return userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));
    }


    @GetMapping("/latest")
    public ResponseEntity<Map<String, Object>> getLatestPipeline() {
        var user = getCurrentUser();

        // Trouver le pipeline le plus récent de l'utilisateur
        PipelineExecution latest = pipelineExecutionRepository
                .findFirstByUserOrderByCreatedAtDesc(user);

        if (latest == null) {
            return ResponseEntity.notFound().build();
        }

        Map<String, Object> response = new HashMap<>();
        response.put("type", "pipeline");
        response.put("id", latest.getGitlabPipelineId());
        response.put("environmentId", latest.getEnvironment().getId());
        response.put("createdAt", latest.getCreatedAt());

        return ResponseEntity.ok(response);
    }



    /**
     * GET /api/pipelines
     * Liste tous les pipelines lancés par l'utilisateur (tous environnements), avec détails type GitLab.
     */
    @GetMapping
    public ResponseEntity<List<Map<String, Object>>> listPipelines(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        var user = getCurrentUser();
        List<EphemeralEnvironment> envs = environmentRepository.findMyEnvironments(user);

        // BDD-first: ne pas appeler GitLab ici (sinon 100+ pipelines => énorme latence)
        List<PipelineExecution> executions = pipelineExecutionRepository
                .findByEnvironmentInOrderByCreatedAtDesc(envs, PageRequest.of(page, Math.min(size, 50)));

        List<Map<String, Object>> result = executions.stream()
                .map(this::buildPipelineResponseFromDb)
                .collect(Collectors.toList());

        return ResponseEntity.ok(result);
    }

    private Map<String, Object> buildPipelineResponseFromDb(PipelineExecution execution) {
        Map<String, Object> map = new HashMap<>();
        EphemeralEnvironment env = execution.getEnvironment();

        map.put("environmentId", env.getId());
        map.put("environmentName", env.getEnvironmentName());
        map.put("gitBranch", env.getGitBranch());
        map.put("pipelineId", execution.getGitlabPipelineId());
        map.put("pipelineStatus", execution.getStatus().name());
        map.put("createdAt", execution.getCreatedAt());
        map.put("finishedAt", execution.getFinishedAt());

        // Enrichissement depuis stages_json (si existant)
        map.put("status", execution.getStatus().name());
        if (execution.getStagesJson() != null) {
            map.put("jobs", pipelineStageSyncService.getJobsFromStagesJson(execution));
            Object jobStatusCount = pipelineStageSyncService.getJobStatusCountFromStagesJson(execution);
            if (jobStatusCount instanceof Map && ((Map<?, ?>) jobStatusCount).isEmpty()) {
                jobStatusCount = Map.of(execution.getStatus().name(), 1L);
            }
            map.put("jobStatusCount", jobStatusCount);
            map.put("webUrl", execution.getStagesJson().get("webUrl"));
            map.put("ref", execution.getStagesJson().get("ref"));
            map.put("shortSha", execution.getStagesJson().get("shortSha"));
            map.put("duration", execution.getStagesJson().get("duration"));
            map.put("totalJobs", execution.getStagesJson().get("totalJobs"));
            map.put("lastSyncedAt", execution.getStagesJson().get("lastSyncedAt"));
        } else {
            map.put("jobs", List.of());
            map.put("jobStatusCount", Map.of(execution.getStatus().name(), 1L));
        }
        map.put("dataSource", "database");
        return map;
    }

    /**
     * Rafraîchit en arrière-plan (si demandé, ou si la synchro est trop ancienne) sans bloquer la réponse HTTP.
     * Objectif: BDD d'abord, GitLab jamais bloquant.
     */
    private void maybeRefreshAsync(PipelineExecution execution, boolean refreshExplicit) {
        Long pid = execution.getGitlabPipelineId();
        if (pid == null || pid <= 0) {
            return;
        }
        boolean stale = isStagesJsonStale(execution);
        if (!refreshExplicit && !stale) {
            return;
        }
        java.util.concurrent.CompletableFuture.runAsync(() -> {
            try {
                pipelineStageSyncService.syncStagesForPipeline(pid);
            } catch (Exception e) {
                log.debug("Refresh async pipeline {} ignoré: {}", pid, e.getMessage());
            }
        });
    }

    private boolean isStagesJsonStale(PipelineExecution execution) {
        Map<String, Object> stages = execution.getStagesJson();
        if (stages == null) {
            return true;
        }
        Object last = stages.get("lastSyncedAt");
        if (!(last instanceof String s) || s.isBlank()) {
            return true;
        }
        try {
            Instant t = Instant.parse(s);
            return Duration.between(t, Instant.now()).getSeconds() > 8;
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * GET /api/pipelines/by-environment/{envId}
     * Détail d'un pipeline + scans pour un environnement.
     */
    @GetMapping("/by-environment/{envId}")
    public ResponseEntity<PipelineScanResponse> getByEnvironment(
            @PathVariable UUID envId,
            @RequestParam(name = "includeReports", defaultValue = "false") boolean includeReports,
            @RequestParam(name = "refresh", defaultValue = "false") boolean refresh
    ) {
        var user = getCurrentUser();
        EphemeralEnvironment env = environmentRepository.findByIdAndRequestedBy(envId, user)
                .orElseThrow(() -> new RuntimeException("Environnement non trouvé"));
        PipelineExecution latest = pipelineExecutionRepository.findFirstByEnvironmentOrderByCreatedAtDesc(env)
                .orElseThrow(() -> new RuntimeException("Aucun pipeline pour cet environnement"));
        Long pipelineId = latest.getGitlabPipelineId();

        // BDD-first: retour immédiat sans GitLab (suffisant pour UI: jobs/status/aggregate-report)
        if (!includeReports) {
            // En mode "refresh" (live), on force une synchro best-effort AVANT de répondre,
            // sinon après un retry GitLab l'UI continue d'afficher l'ancien job failed/skipped.
            if (refresh && pipelineId != null && pipelineId > 0) {
                try {
                    pipelineStageSyncService.syncStagesForPipeline(pipelineId);
                    latest = pipelineExecutionRepository.findFirstByEnvironmentOrderByCreatedAtDesc(env)
                            .orElse(latest);
                } catch (Exception e) {
                    // fallback: on renvoie quand même la dernière vue BDD
                    maybeRefreshAsync(latest, true);
                }
            } else {
                maybeRefreshAsync(latest, refresh);
            }

            Object jobs = latest.getStagesJson() != null
                    ? pipelineStageSyncService.getJobsFromStagesJson(latest)
                    : List.<Map<String, Object>>of();
            Object jobStatusCount = latest.getStagesJson() != null
                    ? pipelineStageSyncService.getJobStatusCountFromStagesJson(latest)
                    : Map.of(latest.getStatus().name(), 1L);
            if (jobStatusCount instanceof Map && ((Map<?, ?>) jobStatusCount).isEmpty()) {
                jobStatusCount = Map.of(latest.getStatus().name(), 1L);
            }
            return ResponseEntity.ok(PipelineScanResponse.builder()
                    .pipelineId(pipelineId)
                    .status(latest.getStagesJson() != null ? (String) latest.getStagesJson().get("status") : latest.getStatus().name())
                    .webUrl(latest.getStagesJson() != null ? (String) latest.getStagesJson().get("webUrl") : null)
                    .jobStatusCount(jobStatusCount)
                    .jobs(jobs)
                    .securityReports(Map.of())
                    .dataSource("database")
                    .build());
        }

        // Si pas d'ID GitLab valide, retourner les infos de base depuis la BDD
        if (pipelineId == null || pipelineId <= 0) {
            log.warn("Pipeline execution {} n'a pas d'ID GitLab valide (gitlabPipelineId={}). Retour des infos de base depuis la BDD.", latest.getId(), pipelineId);
            PipelineScanResponse response = PipelineScanResponse.builder()
                    .pipelineId(pipelineId)
                    .status(latest.getStatus().name())
                    .webUrl(null)
                    .jobStatusCount(Map.of(latest.getStatus().name(), 1L))
                    .jobs(List.of())
                    .securityReports(Map.of())
                    .dataSource("database")
                    .build();
            return ResponseEntity.ok(response);
        }

        try {
            Map<String, Object> summary = gitLabService.getPipelineSummary(pipelineId);
            pipelineStageSyncService.syncStagesForPipeline(pipelineId);
            Map<String, JsonNode> reports = gitLabService.getAllSecurityReports(pipelineId);
            PipelineScanResponse response = PipelineScanResponse.builder()
                    .pipelineId(pipelineId)
                    .status((String) summary.get("status"))
                    .webUrl((String) summary.get("webUrl"))
                    .jobStatusCount(summary.get("jobStatusCount"))
                    .jobs(summary.get("jobs"))
                    .securityReports(reports)
                    .dataSource("gitlab")
                    .build();
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Erreur récupération pipeline GitLab {}: {}, fallback BDD (stages_json)", pipelineId, e.getMessage());
            Object jobs = latest.getStagesJson() != null
                    ? pipelineStageSyncService.getJobsFromStagesJson(latest)
                    : List.<Map<String, Object>>of();
            Object jobStatusCount = latest.getStagesJson() != null
                    ? pipelineStageSyncService.getJobStatusCountFromStagesJson(latest)
                    : Map.of(latest.getStatus().name(), 1L);
            if (jobStatusCount instanceof Map && ((Map<?, ?>) jobStatusCount).isEmpty()) {
                jobStatusCount = Map.of(latest.getStatus().name(), 1L);
            }
            PipelineScanResponse response = PipelineScanResponse.builder()
                    .pipelineId(pipelineId)
                    .status(latest.getStatus().name())
                    .webUrl(latest.getStagesJson() != null ? (String) latest.getStagesJson().get("webUrl") : null)
                    .jobStatusCount(jobStatusCount)
                    .jobs(jobs)
                    .securityReports(Map.of())
                    .dataSource("database")
                    .build();
            return ResponseEntity.ok(response);
        }
    }

    /**
     * GET /api/pipelines/{pipelineId}
     * Détail d'un pipeline + scans à partir de son ID GitLab.
     */
    @GetMapping("/by-id/{pipelineId}")
    public ResponseEntity<PipelineScanResponse> getByPipelineId(
            @PathVariable Long pipelineId,
            @RequestParam(name = "includeReports", defaultValue = "false") boolean includeReports,
            @RequestParam(name = "refresh", defaultValue = "false") boolean refresh
    ) {
        var user = getCurrentUser();
        PipelineExecution execution = pipelineExecutionRepository.findByGitlabPipelineId(pipelineId)
                .orElseThrow(() -> new RuntimeException("Pipeline inconnu"));

        if (!execution.getEnvironment().getRequestedBy().getId().equals(user.getId())) {
            return ResponseEntity.status(403).build();
        }

        if (!includeReports) {
            if (refresh) {
                try {
                    pipelineStageSyncService.syncStagesForPipeline(pipelineId);
                    execution = pipelineExecutionRepository.findByGitlabPipelineId(pipelineId).orElse(execution);
                } catch (Exception e) {
                    maybeRefreshAsync(execution, true);
                }
            } else {
                maybeRefreshAsync(execution, refresh);
            }
            Object jobs = execution.getStagesJson() != null
                    ? pipelineStageSyncService.getJobsFromStagesJson(execution)
                    : List.<Map<String, Object>>of();
            Object jobStatusCount = execution.getStagesJson() != null
                    ? pipelineStageSyncService.getJobStatusCountFromStagesJson(execution)
                    : Map.of(execution.getStatus().name(), 1L);
            if (jobStatusCount instanceof Map && ((Map<?, ?>) jobStatusCount).isEmpty()) {
                jobStatusCount = Map.of(execution.getStatus().name(), 1L);
            }
            return ResponseEntity.ok(PipelineScanResponse.builder()
                    .pipelineId(pipelineId)
                    .status(execution.getStagesJson() != null ? (String) execution.getStagesJson().get("status") : execution.getStatus().name())
                    .webUrl(execution.getStagesJson() != null ? (String) execution.getStagesJson().get("webUrl") : null)
                    .jobStatusCount(jobStatusCount)
                    .jobs(jobs)
                    .securityReports(Map.of())
                    .dataSource("database")
                    .build());
        }

        try {
            Map<String, Object> summary = gitLabService.getPipelineSummary(pipelineId);
            pipelineStageSyncService.syncStagesForPipeline(pipelineId);
            Map<String, JsonNode> reports = gitLabService.getAllSecurityReports(pipelineId);
            return ResponseEntity.ok(PipelineScanResponse.builder()
                    .pipelineId(pipelineId)
                    .status((String) summary.get("status"))
                    .webUrl((String) summary.get("webUrl"))
                    .jobStatusCount(summary.get("jobStatusCount"))
                    .jobs(summary.get("jobs"))
                    .securityReports(reports)
                    .dataSource("gitlab")
                    .build());
        } catch (Exception e) {
            log.error("Erreur récupération pipeline GitLab {}: {}, fallback BDD (stages_json)", pipelineId, e.getMessage());
            Object jobs = execution.getStagesJson() != null
                    ? pipelineStageSyncService.getJobsFromStagesJson(execution)
                    : List.<Map<String, Object>>of();
            Object jobStatusCount = execution.getStagesJson() != null
                    ? pipelineStageSyncService.getJobStatusCountFromStagesJson(execution)
                    : Map.of(execution.getStatus().name(), 1L);
            if (jobStatusCount instanceof Map && ((Map<?, ?>) jobStatusCount).isEmpty()) {
                jobStatusCount = Map.of(execution.getStatus().name(), 1L);
            }
            return ResponseEntity.ok(PipelineScanResponse.builder()
                    .pipelineId(pipelineId)
                    .status(execution.getStatus().name())
                    .webUrl(execution.getStagesJson() != null ? (String) execution.getStagesJson().get("webUrl") : null)
                    .jobStatusCount(jobStatusCount)
                    .jobs(jobs)
                    .securityReports(Map.of())
                    .dataSource("database")
                    .build());
        }
    }
    /**
     * GET /api/pipelines/jobs/{jobId}/logs
     * Récupère les logs d'un job GitLab (équivalent à l’onglet Logs de GitLab).
     */
    @GetMapping(value = "/jobs/{jobId}/logs", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> getJobLogs(@PathVariable Long jobId) {
        try {
            String logs = gitLabService.getJobLogs(jobId);
            return ResponseEntity.ok(logs);
        } catch (Exception e) {
            log.error("❌ Erreur récupération logs job {}: {}", jobId, e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * GET /api/pipelines/jobs/{jobId}/scan
     * Récupère le JSON du résultat de scan pour un job donné (Trivy/SonarQube...).
     */
    @GetMapping(value = "/jobs/{jobId}/scan", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JsonNode> getJobScan(@PathVariable Long jobId) {
        try {
            JsonNode report = gitLabService.getScanResults(jobId);
            if (report == null) {
                return ResponseEntity.notFound().build();
            }
            return ResponseEntity.ok(report);
        } catch (Exception e) {
            log.error("❌ Erreur récupération scan results job {}: {}", jobId, e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * POST /api/pipelines/{pipelineId}/cancel
     * Annule un pipeline en cours (si l'utilisateur en est propriétaire).
     */
    @PostMapping("/{pipelineId}/cancel")
    public ResponseEntity<Void> cancelPipeline(@PathVariable Long pipelineId) {
        var user = getCurrentUser();
        PipelineExecution execution = pipelineExecutionRepository.findByGitlabPipelineId(pipelineId)
                .orElseThrow(() -> new RuntimeException("Pipeline inconnu"));
        if (!execution.getEnvironment().getRequestedBy().getId().equals(user.getId())) {
            return ResponseEntity.status(403).build();
        }
        try {
            gitLabService.cancelPipeline(pipelineId);
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            log.error("❌ Annulation pipeline {}: {}", pipelineId, e.getMessage());
            return ResponseEntity.notFound().build();
        }

    }

    /**
     * POST /api/pipelines/jobs/{jobId}/retry
     * Relance un job (retry) sans relancer tout le pipeline.
     */
    @PostMapping("/jobs/{jobId}/retry")
    public ResponseEntity<Void> retryJob(@PathVariable Long jobId) {
        var user = getCurrentUser();
        try {
            // Vérifier que le job appartient bien à un pipeline de l'utilisateur
            var job = gitLabService.getJob(jobId);
            if (job == null || job.getPipeline() == null || job.getPipeline().getId() == null) {
                return ResponseEntity.notFound().build();
            }
            Long pipelineId = job.getPipeline().getId();
            PipelineExecution execution = pipelineExecutionRepository.findByGitlabPipelineId(pipelineId)
                    .orElseThrow(() -> new RuntimeException("Pipeline inconnu"));
            if (!execution.getEnvironment().getRequestedBy().getId().equals(user.getId())) {
                return ResponseEntity.status(403).build();
            }
            gitLabService.retryJob(jobId);
            // refresh async best-effort
            maybeRefreshAsync(execution, true);
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            log.error("❌ Retry job {}: {}", jobId, e.getMessage());
            return ResponseEntity.internalServerError().build();
        }
    }

    // Dans PipelineController.java

    /**
     * DELETE /api/pipelines/{pipelineId}
     * Supprime un pipeline (dans GitLab et en base)
     */
    // Dans PipelineController.java - Méthode deletePipeline
    // Dans PipelineController.java - Méthode deletePipeline
    // Dans PipelineController.java - Méthode deletePipeline CORRIGÉE
    @DeleteMapping("/{pipelineId}")
    public ResponseEntity<Void> deletePipeline(@PathVariable Long pipelineId) {
        var user = getCurrentUser();

        PipelineExecution execution = pipelineExecutionRepository.findByGitlabPipelineId(pipelineId)
                .orElseThrow(() -> new RuntimeException("Pipeline inconnu"));

        if (!execution.getEnvironment().getRequestedBy().getId().equals(user.getId())) {
            return ResponseEntity.status(403).build();
        }

        EphemeralEnvironment env = execution.getEnvironment();

        try {
            // Supprimer le pipeline
            pipelineExecutionRepository.delete(execution);
            log.info("✅ Pipeline {} supprimé", pipelineId);

            // 🔥 CORRECTION: Un environnement = Un pipeline
            // Donc on supprime TOUJOURS l'environnement quand on supprime son pipeline
            environmentRepository.delete(env);
            log.info("✅ Environnement {} supprimé (associé au pipeline)", env.getId());

            return ResponseEntity.noContent().build();

        } catch (Exception e) {
            log.error("❌ Erreur suppression pipeline: {}", e.getMessage());
            return ResponseEntity.internalServerError().build();
        }
    }
}

