package com.backend.devsecopsplatform_backend.controller.pipeline;

import com.backend.devsecopsplatform_backend.controller.environment.PipelineScanResponse;
import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.service.GitLabService;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/pipelines")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "http://localhost:4200")
public class PipelineController {

    private final EphemeralEnvironmentRepository environmentRepository;
    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final UserRepository userRepository;
    private final GitLabService gitLabService;

    private com.backend.devsecopsplatform_backend.entity.User getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getName() == null) {
            throw new RuntimeException("Utilisateur non authentifié");
        }
        return userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));
    }

    /**
     * GET /api/pipelines
     * Liste tous les pipelines lancés par l'utilisateur (tous environnements), avec détails type GitLab.
     */
    @GetMapping
    public ResponseEntity<List<Map<String, Object>>> listPipelines() {
        var user = getCurrentUser();
        List<EphemeralEnvironment> envs = environmentRepository.findMyEnvironments(user);
        List<PipelineExecution> executions = pipelineExecutionRepository
                .findByEnvironmentInOrderByCreatedAtDesc(envs, PageRequest.of(0, 50));

        List<Map<String, Object>> result = new ArrayList<>();
        for (PipelineExecution execution : executions) {
            EphemeralEnvironment env = execution.getEnvironment();
            Map<String, Object> map = new HashMap<>();
            map.put("environmentId", env.getId());
            map.put("environmentName", env.getEnvironmentName());
            map.put("gitBranch", env.getGitBranch());
            map.put("pipelineId", execution.getGitlabPipelineId());
            map.put("pipelineStatus", execution.getStatus().name());
            map.put("createdAt", execution.getCreatedAt());
            map.put("finishedAt", execution.getFinishedAt());
            map.put("createdByUsername", env.getRequestedBy() != null ? env.getRequestedBy().getUsername() : null);

            Integer pipelineId = execution.getGitlabPipelineId();
            if (pipelineId != null && pipelineId > 0) {
                try {
                    Map<String, Object> summary = gitLabService.getPipelineSummary(pipelineId.longValue());
                    map.put("status", summary.get("status"));
                    map.put("webUrl", summary.get("webUrl"));
                    map.put("ref", summary.get("ref"));
                    map.put("shortSha", summary.get("shortSha"));
                    map.put("duration", summary.get("duration"));
                    @SuppressWarnings("unchecked")
                    List<Map<String, Object>> jobs = (List<Map<String, Object>>) summary.get("jobs");
                    map.put("jobs", jobs != null ? jobs : List.of());
                } catch (Exception e) {
                    log.warn("Enrichissement pipeline {} ignoré: {}", pipelineId, e.getMessage());
                    map.put("status", execution.getStatus().name());
                    map.put("jobs", List.<Map<String, Object>>of());
                }
            } else {
                map.put("status", execution.getStatus().name());
                map.put("jobs", List.<Map<String, Object>>of());
            }
            result.add(map);
        }
        return ResponseEntity.ok(result);
    }

    /**
     * GET /api/pipelines/by-environment/{envId}
     * Détail d'un pipeline + scans pour un environnement.
     */
    @GetMapping("/by-environment/{envId}")
    public ResponseEntity<PipelineScanResponse> getByEnvironment(@PathVariable UUID envId) {
        var user = getCurrentUser();
        EphemeralEnvironment env = environmentRepository.findByIdAndRequestedBy(envId, user)
                .orElseThrow(() -> new RuntimeException("Environnement non trouvé"));
        PipelineExecution latest = pipelineExecutionRepository.findFirstByEnvironmentOrderByCreatedAtDesc(env)
                .orElseThrow(() -> new RuntimeException("Aucun pipeline pour cet environnement"));
        Integer pipelineId = latest.getGitlabPipelineId();
        if (pipelineId == null || pipelineId <= 0) {
            throw new RuntimeException("ID pipeline GitLab invalide");
        }
        Map<String, Object> summary = gitLabService.getPipelineSummary(pipelineId.longValue());
        Map<String, JsonNode> reports = gitLabService.getAllSecurityReports(pipelineId.longValue());
        PipelineScanResponse response = PipelineScanResponse.builder()
                .pipelineId(pipelineId)
                .status((String) summary.get("status"))
                .webUrl((String) summary.get("webUrl"))
                .jobStatusCount(summary.get("jobStatusCount"))
                .jobs(summary.get("jobs"))
                .securityReports(reports)
                .build();
        return ResponseEntity.ok(response);
    }

    /**
     * GET /api/pipelines/{pipelineId}
     * Détail d'un pipeline + scans à partir de son ID GitLab.
     */
    @GetMapping("/{pipelineId}")
    public ResponseEntity<PipelineScanResponse> getByPipelineId(@PathVariable Integer pipelineId) {
        var user = getCurrentUser();
        PipelineExecution execution = pipelineExecutionRepository.findByGitlabPipelineId(pipelineId)
                .orElseThrow(() -> new RuntimeException("Pipeline inconnu"));
        if (!execution.getEnvironment().getRequestedBy().getId().equals(user.getId())) {
            return ResponseEntity.status(403).build();
        }
        if (pipelineId == null || pipelineId <= 0) {
            throw new RuntimeException("ID pipeline GitLab invalide");
        }
        Map<String, Object> summary = gitLabService.getPipelineSummary(pipelineId.longValue());
        Map<String, JsonNode> reports = gitLabService.getAllSecurityReports(pipelineId.longValue());
        PipelineScanResponse response = PipelineScanResponse.builder()
                .pipelineId(pipelineId)
                .status((String) summary.get("status"))
                .webUrl((String) summary.get("webUrl"))
                .jobStatusCount(summary.get("jobStatusCount"))
                .jobs(summary.get("jobs"))
                .securityReports(reports)
                .build();
        return ResponseEntity.ok(response);
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
    public ResponseEntity<Void> cancelPipeline(@PathVariable Integer pipelineId) {
        var user = getCurrentUser();
        PipelineExecution execution = pipelineExecutionRepository.findByGitlabPipelineId(pipelineId)
                .orElseThrow(() -> new RuntimeException("Pipeline inconnu"));
        if (!execution.getEnvironment().getRequestedBy().getId().equals(user.getId())) {
            return ResponseEntity.status(403).build();
        }
        try {
            gitLabService.cancelPipeline(pipelineId.longValue());
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            log.error("❌ Annulation pipeline {}: {}", pipelineId, e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }
}

