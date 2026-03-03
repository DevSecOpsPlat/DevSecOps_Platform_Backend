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
import java.util.stream.Collectors;

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
            @RequestParam(defaultValue = "10") int size) {  // ← LIMITER À 10

        var user = getCurrentUser();
        List<EphemeralEnvironment> envs = environmentRepository.findMyEnvironments(user);

        // Ne prendre que les 10 plus récents
        List<PipelineExecution> executions = pipelineExecutionRepository
                .findByEnvironmentInOrderByCreatedAtDesc(envs, PageRequest.of(page, Math.min(size, 20)));

        // Récupérer en parallèle
        List<Map<String, Object>> result = executions.parallelStream()
                .map(this::buildPipelineResponse)
                .collect(Collectors.toList());

        return ResponseEntity.ok(result);
    }

    private Map<String, Object> buildPipelineResponse(PipelineExecution execution) {
        Map<String, Object> map = new HashMap<>();
        EphemeralEnvironment env = execution.getEnvironment();

        map.put("environmentId", env.getId());
        map.put("environmentName", env.getEnvironmentName());
        map.put("gitBranch", env.getGitBranch());
        map.put("pipelineId", execution.getGitlabPipelineId());
        map.put("pipelineStatus", execution.getStatus().name());
        map.put("createdAt", execution.getCreatedAt());
        map.put("finishedAt", execution.getFinishedAt());

        Long pipelineId = execution.getGitlabPipelineId();
        if (pipelineId != null && pipelineId > 0) {
            try {
                // Essayer GitLab avec timeout
                Map<String, Object> summary = gitLabService.getPipelineSummary(pipelineId);
                map.putAll(summary);
            } catch (Exception e) {
                log.debug("GitLab non disponible pour pipeline {}, utilisation cache", pipelineId);
                map.put("status", execution.getStatus().name());
                map.put("jobs", List.of());
            }
        }
        return map;
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
        Long pipelineId = latest.getGitlabPipelineId();

        // Si pas d'ID GitLab valide, retourner les infos de base depuis la BDD
        if (pipelineId == null || pipelineId <= 0) {
            log.warn("Pipeline execution {} n'a pas d'ID GitLab valide (gitlabPipelineId={}). Retour des infos de base depuis la BDD.", latest.getId(), pipelineId);
            PipelineScanResponse response = PipelineScanResponse.builder()
                    .pipelineId(pipelineId) // Long directement
                    .status(latest.getStatus().name())
                    .webUrl(null)
                    .jobStatusCount(Map.of(latest.getStatus().name(), 1L))
                    .jobs(List.of())
                    .securityReports(Map.of())
                    .build();
            return ResponseEntity.ok(response);
        }

        try {
            Map<String, Object> summary = gitLabService.getPipelineSummary(pipelineId);
            Map<String, JsonNode> reports = gitLabService.getAllSecurityReports(pipelineId);
            PipelineScanResponse response = PipelineScanResponse.builder()
                    .pipelineId(pipelineId)
                    .status((String) summary.get("status"))
                    .webUrl((String) summary.get("webUrl"))
                    .jobStatusCount(summary.get("jobStatusCount"))
                    .jobs(summary.get("jobs"))
                    .securityReports(reports)
                    .build();
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Erreur récupération pipeline GitLab {}: {}", pipelineId, e.getMessage());
            // Fallback : retourner les infos de base depuis la BDD
            PipelineScanResponse response = PipelineScanResponse.builder()
                    .pipelineId(pipelineId) // Long directement
                    .status(latest.getStatus().name())
                    .webUrl(null)
                    .jobStatusCount(Map.of(latest.getStatus().name(), 1L))
                    .jobs(List.of())
                    .securityReports(Map.of())
                    .build();
            return ResponseEntity.ok(response);
        }
    }

    /**
     * GET /api/pipelines/{pipelineId}
     * Détail d'un pipeline + scans à partir de son ID GitLab.
     */
    @GetMapping("/by-id/{pipelineId}")
    public ResponseEntity<PipelineScanResponse> getByPipelineId(@PathVariable Long pipelineId) {
        var user = getCurrentUser();
        PipelineExecution execution = pipelineExecutionRepository.findByGitlabPipelineId(pipelineId)
                .orElseThrow(() -> new RuntimeException("Pipeline inconnu"));

        if (!execution.getEnvironment().getRequestedBy().getId().equals(user.getId())) {
            return ResponseEntity.status(403).build();
        }

        Map<String, Object> summary = gitLabService.getPipelineSummary(pipelineId);
        Map<String, JsonNode> reports = gitLabService.getAllSecurityReports(pipelineId);

        return ResponseEntity.ok(PipelineScanResponse.builder()
                .pipelineId(pipelineId)
                .status((String) summary.get("status"))
                .webUrl((String) summary.get("webUrl"))
                .jobStatusCount(summary.get("jobStatusCount"))
                .jobs(summary.get("jobs"))
                .securityReports(reports)
                .build());
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

