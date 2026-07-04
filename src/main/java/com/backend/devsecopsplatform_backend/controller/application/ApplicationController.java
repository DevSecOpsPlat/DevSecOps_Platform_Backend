package com.backend.devsecopsplatform_backend.controller.application;


import com.backend.devsecopsplatform_backend.service.application.ApplicationService;
import com.backend.devsecopsplatform_backend.service.environment.EnvironmentService;
import com.backend.devsecopsplatform_backend.service.PipelineStageSyncService;
import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.PipelineStatus;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/applications")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local","http://envirotest.local:4200"})
public class ApplicationController {

    private final ApplicationService applicationService;
    private final EphemeralEnvironmentRepository environmentRepository;
    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final PipelineStageSyncService pipelineStageSyncService;
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
     * GET /api/applications/{id}/deployments/metrics
     * Compteurs globaux (toutes exécutions de l’app), indépendants de la pagination de l’historique.
     */
    @GetMapping("/{id}/deployments/metrics")
    public ResponseEntity<DeploymentMetricsDto> getDeploymentMetrics(
            @PathVariable UUID id,
            @RequestParam(name = "branch", required = false) String branch
    ) {
        String normalizedBranch = (branch == null || branch.isBlank()) ? null : branch.trim();
        long total = normalizedBranch == null
                ? pipelineExecutionRepository.countByApplicationId(id)
                : pipelineExecutionRepository.countByApplicationIdAndBranch(id, normalizedBranch);
        long success = 0;
        long failed = 0;
        long canceled = 0;
        long pending = 0;
        long running = 0;
        long skipped = 0;
        List<Object[]> rows = normalizedBranch == null
                ? pipelineExecutionRepository.countByApplicationIdGroupByStatus(id)
                : pipelineExecutionRepository.countByApplicationIdAndBranchGroupByStatus(id, normalizedBranch);
        for (Object[] row : rows) {
            if (row[0] == null || row[1] == null) {
                continue;
            }
            PipelineStatus st = (PipelineStatus) row[0];
            long c = ((Number) row[1]).longValue();
            switch (st) {
                case SUCCESS -> success += c;
                case FAILED -> failed += c;
                case CANCELED -> canceled += c;
                case PENDING -> pending += c;
                case RUNNING -> running += c;
                case SKIPPED -> skipped += c;
            }
        }
        DeploymentMetricsDto dto = DeploymentMetricsDto.builder()
                .total(total)
                .success(success)
                .failed(failed)
                .canceled(canceled)
                .pending(pending)
                .running(running)
                .skipped(skipped)
                .build();
        return ResponseEntity.ok(dto);
    }

    /**
     * GET /api/applications/{id}/deployments
     * Historique des déploiements (BDD uniquement — pas d’appel GitLab ici, pour éviter des dizaines
     * de requêtes réseau et des temps de réponse de plusieurs dizaines de secondes au refresh du dashboard).
     * Jobs / shortSha proviennent de {@code stages_json} si la synchro pipeline a déjà tourné.
     */
    @GetMapping("/{id}/deployments")
    public ResponseEntity<List<DeploymentHistoryItem>> getDeploymentHistory(
            @PathVariable UUID id,
            @RequestParam(name = "branch", required = false) String branch,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "50") int size
    ) {
        try {
            List<EphemeralEnvironment> envs = environmentRepository.findByService_Id(id);

            List<DeploymentHistoryItem> history = envs.stream()
                    .filter(env -> branch == null || branch.isBlank() || branch.equals(env.getGitBranch()))
                    .flatMap(env -> pipelineExecutionRepository.findByEnvironmentOrderByCreatedAtDesc(env).stream()
                            .map(exec -> buildDeploymentHistoryItem(env, exec))
                    )
                    .sorted((a, b) -> {
                        if (a.getCreatedAt() == null && b.getCreatedAt() == null) return 0;
                        if (a.getCreatedAt() == null) return 1;
                        if (b.getCreatedAt() == null) return -1;
                        return b.getCreatedAt().compareTo(a.getCreatedAt());
                    })
                    .collect(Collectors.toList());

            int safePage = Math.max(0, page);
            int safeSize = Math.min(Math.max(size, 1), 100);
            int from = safePage * safeSize;
            if (from >= history.size()) {
                return ResponseEntity.ok(List.of());
            }
            int to = Math.min(from + safeSize, history.size());
            return ResponseEntity.ok(history.subList(from, to));
        } catch (Exception e) {
            log.error("❌ Erreur récupération historique déploiements: {}", e.getMessage());
            return ResponseEntity.internalServerError().build();
        }
    }

    private DeploymentHistoryItem buildDeploymentHistoryItem(EphemeralEnvironment env, PipelineExecution exec) {
        List<Map<String, Object>> jobs = pipelineStageSyncService.getJobsFromStagesJson(exec);
        String shortSha = shortShaFromStagesJson(exec);

        DeploymentHistoryItem item = new DeploymentHistoryItem();
        item.setEnvironmentId(env.getId());
        item.setEnvironmentName(env.getEnvironmentName());
        item.setGitBranch(env.getGitBranch());
        item.setPipelineId(exec.getGitlabPipelineId());
        item.setPipelineStatus(exec.getStatus() != null ? exec.getStatus().name() : null);
        item.setEnvironmentStatus(env.getStatus() != null ? env.getStatus().name() : null);
        item.setShortSha(shortSha);
        item.setCommitMessage(null);
        item.setCreatedAt(exec.getCreatedAt());
        item.setFinishedAt(exec.getFinishedAt());
        item.setTriggeredByUsername(env.getRequestedBy() != null ? env.getRequestedBy().getUsername() : null);
        item.setJobs(jobs);
        item.setDeploymentUrl(environmentService.resolveDeploymentPublicUrl(env));
        item.setTtlHours(env.getTtlHours());
        item.setExpiresAt(env.getExpiresAt());
        return item;
    }

    private static String shortShaFromStagesJson(PipelineExecution exec) {
        Map<String, Object> stages = exec.getStagesJson();
        if (stages == null) {
            return null;
        }
        Object sha = stages.get("shortSha");
        if (sha instanceof String s && !s.isBlank()) {
            return s.length() > 8 ? s.substring(0, 8) : s;
        }
        return null;
    }
}