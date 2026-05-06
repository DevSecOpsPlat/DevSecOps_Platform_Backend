package com.backend.devsecopsplatform_backend.controller.application;


import com.backend.devsecopsplatform_backend.service.application.ApplicationService;
import com.backend.devsecopsplatform_backend.service.environment.EnvironmentService;
import com.backend.devsecopsplatform_backend.service.GitLabService;
import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/applications")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "http://localhost:4200")
public class ApplicationController {

    private final ApplicationService applicationService;
    private final EphemeralEnvironmentRepository environmentRepository;
    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final GitLabService gitLabService;
    private final EnvironmentService environmentService;

    /**
     * POST /api/applications
     * Crée une nouvelle application avec token GitHub chiffré
     */
    @PostMapping
    public ResponseEntity<ApplicationResponse> createApplication(
            @Valid @RequestBody CreateApplicationRequest request) {

        log.info("📥 Création application: {}", request.getName());

        try {
            ApplicationResponse response = applicationService.createApplication(request);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("❌ Erreur création application: {}", e.getMessage());
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * GET /api/applications
     * Liste les applications de l'utilisateur connecté
     */
    @GetMapping
    public ResponseEntity<List<ApplicationResponse>> getMyApplications() {
        log.info("📋 Récupération de mes applications");

        List<ApplicationResponse> apps = applicationService.getMyApplications();
        return ResponseEntity.ok(apps);
    }

    /**
     * GET /api/applications/{id}
     * Récupère une application par ID
     */
    @GetMapping("/{id}")
    public ResponseEntity<ApplicationResponse> getApplication(@PathVariable UUID id) {
        log.info("🔍 Récupération application: {}", id);

        try {
            ApplicationResponse app = applicationService.getApplicationById(id);
            return ResponseEntity.ok(app);
        } catch (Exception e) {
            log.error("❌ Application non trouvée: {}", id);
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * GET /api/applications/{id}/deployments
     * Historique des déploiements (pipelines) pour une application, optionnellement filtré par branche.
     */
    @GetMapping("/{id}/deployments")
    public ResponseEntity<List<DeploymentHistoryItem>> getDeploymentHistory(
            @PathVariable UUID id,
            @RequestParam(name = "branch", required = false) String branch
    ) {
        try {
            List<EphemeralEnvironment> envs = environmentRepository.findByApplication_Id(id);

            List<DeploymentHistoryItem> history = envs.stream()
                    .filter(env -> branch == null || branch.isBlank() || branch.equals(env.getGitBranch()))
                    .flatMap(env -> pipelineExecutionRepository.findByEnvironmentOrderByCreatedAtDesc(env).stream()
                            .map(exec -> {
                                String shortSha = null;
                                String commitMessage = null;
                                List<Map<String, Object>> jobs = null; // ← AJOUTER

                                if (exec.getGitlabPipelineId() != null) {
                                    try {
                                        var p = gitLabService.getPipeline(exec.getGitlabPipelineId());
                                        if (p.getSha() != null) {
                                            shortSha = p.getSha().length() >= 8 ? p.getSha().substring(0, 8) : p.getSha();
                                        }

                                        // 🔥 RÉCUPÉRER LES JOBS DEPUIS GITLAB
                                        jobs = gitLabService.getPipelineJobs(exec.getGitlabPipelineId())
                                                .stream()
                                                .map(job -> {
                                                    Map<String, Object> jobMap = new HashMap<>();
                                                    jobMap.put("id", job.getId());
                                                    jobMap.put("name", job.getName());
                                                    jobMap.put("status", job.getStatus() != null ? job.getStatus().toString() : "unknown");
                                                    jobMap.put("stage", job.getStage());
                                                    jobMap.put("duration", job.getDuration());
                                                    jobMap.put("webUrl", job.getWebUrl());
                                                    return jobMap;
                                                })
                                                .collect(Collectors.toList());

                                    } catch (Exception e) {
                                        log.warn("Impossible de récupérer les jobs pour le pipeline {}: {}",
                                                exec.getGitlabPipelineId(), e.getMessage());
                                    }
                                }

                                // Construction avec tous les champs
                                DeploymentHistoryItem item = new DeploymentHistoryItem();
                                item.setEnvironmentId(env.getId());
                                item.setEnvironmentName(env.getEnvironmentName());
                                item.setGitBranch(env.getGitBranch());
                                item.setPipelineId(exec.getGitlabPipelineId());
                                item.setPipelineStatus(exec.getStatus() != null ? exec.getStatus().name() : null);
                                item.setEnvironmentStatus(env.getStatus() != null ? env.getStatus().name() : null);
                                item.setShortSha(shortSha);
                                item.setCommitMessage(commitMessage);
                                item.setCreatedAt(exec.getCreatedAt());
                                item.setFinishedAt(exec.getFinishedAt());
                                item.setTriggeredByUsername(env.getRequestedBy() != null ? env.getRequestedBy().getUsername() : null);
                                item.setJobs(jobs);
                                item.setDeploymentUrl(environmentService.resolveDeploymentPublicUrl(env));
                                item.setTtlHours(env.getTtlHours());
                                item.setExpiresAt(env.getExpiresAt());

                                return item;
                            })
                    )
                    .sorted((a, b) -> {
                        if (a.getCreatedAt() == null && b.getCreatedAt() == null) return 0;
                        if (a.getCreatedAt() == null) return 1;
                        if (b.getCreatedAt() == null) return -1;
                        return b.getCreatedAt().compareTo(a.getCreatedAt());
                    })
                    .collect(Collectors.toList());

            return ResponseEntity.ok(history);
        } catch (Exception e) {
            log.error("❌ Erreur récupération historique déploiements: {}", e.getMessage());
            return ResponseEntity.internalServerError().build();
        }
    }
}