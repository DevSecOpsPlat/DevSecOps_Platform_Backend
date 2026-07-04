package com.backend.devsecopsplatform_backend.service.environment;

import com.backend.devsecopsplatform_backend.controller.environment.*;
import com.backend.devsecopsplatform_backend.entity.*;
import com.backend.devsecopsplatform_backend.repository.CloudResourceRepository;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.service.application.ApplicationService;
import com.backend.devsecopsplatform_backend.service.EncryptionService;
import com.backend.devsecopsplatform_backend.service.GitHubValidationService;
import com.backend.devsecopsplatform_backend.service.GitLabService;
import com.backend.devsecopsplatform_backend.service.PipelineStageSyncService;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.gitlab4j.api.models.Pipeline;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class EnvironmentService {

    private final ApplicationService applicationService;
    private final GitLabService gitLabService;
    private final GitHubValidationService gitHubValidationService;
    private final EncryptionService encryptionService;
    private final UserRepository userRepository;
    private final EphemeralEnvironmentRepository environmentRepository;
    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final PipelineStageSyncService pipelineStageSyncService;
    private final CloudResourceRepository cloudResourceRepository;

    @Value("${deployment.preview.nip.enabled:false}")
    private boolean nipPreviewEnabled;

    @Value("${deployment.preview.nip.scheme:https}")
    private String nipScheme;

    @Value("${deployment.preview.nip.master-ip:}")
    private String nipMasterIp;

    @Value("${deployment.preview.nip.node-port:30374}")
    private int nipNodePort;

    /**
     * URL publique pour l’UI : d’abord {@link EphemeralEnvironment#getUrl()} (callback pipeline), sinon URL nip.io dérivée si activée.
     */
    public String resolveDeploymentPublicUrl(EphemeralEnvironment e) {
        if (e == null) {
            return null;
        }
        if (e.getUrl() != null && !e.getUrl().isBlank()) {
            return e.getUrl().trim();
        }
        if (!nipPreviewEnabled || nipMasterIp == null || nipMasterIp.isBlank()) {
            return null;
        }
        String scheme = (nipScheme != null && !nipScheme.isBlank()) ? nipScheme.trim().toLowerCase() : "https";
        if (scheme.endsWith("://")) {
            scheme = scheme.substring(0, scheme.length() - 3);
        }
        String id = e.getId().toString().toLowerCase();
        String host = "app-" + id + "." + nipMasterIp.trim() + ".nip.io";
        return scheme + "://" + host + ":" + nipNodePort;
    }

    /**
     * Déploiement : crée ou réutilise une application, crée l'environnement, déclenche le pipeline.
     * Le token GitHub est chiffré en BDD.
     */
    @Transactional
    public DeployResponse deploy(DeployRequest request) {
        User currentUser = getCurrentUser();

        log.info("📥 [Deploy] Données reçues: GIT_REPO_URL={}, GIT_BRANCH={}, sessionDurationHours={}, GITHUB_TOKEN présent={}",
                request.getGitRepositoryUrl(),
                request.getBranch(),
                request.getSessionDurationHours(),
                request.getGithubToken() != null && !request.getGithubToken().isBlank());

        // 1. Valider le repo (et token si fourni)
        if (request.getGithubToken() != null && !request.getGithubToken().isBlank()) {
            boolean valid = gitHubValidationService.validateRepository(
                    request.getGitRepositoryUrl(),
                    request.getGithubToken()
            );
            if (!valid) {
                throw new RuntimeException("Repository GitHub invalide ou token incorrect");
            }
        }

        // 2. Trouver ou créer l'application
        String dockerfilePath = request.getDockerfilePath() != null && !request.getDockerfilePath().isBlank()
                ? request.getDockerfilePath() : "./Dockerfile";
        AppService app = applicationService
                .findOrCreateApplicationForDeploy(
                        currentUser,
                        request.getGitRepositoryUrl(),
                        request.getGithubToken(),
                        dockerfilePath
                );

        // 3. Créer l'environnement éphémère
        int ttlHours = request.getSessionDurationHours() != null ? request.getSessionDurationHours() : 4;
        String envName = "env-" + UUID.randomUUID().toString().substring(0, 8);
        EphemeralEnvironment env = new EphemeralEnvironment();
        env.setEnvironmentName(envName);
        env.setService(app);
        env.setGitBranch(request.getBranch());
        env.setRequestedBy(currentUser);
        env.setStatus(EnvironmentStatus.PENDING);
        env.setTtlHours(ttlHours);
        app.addEphemeralEnvironment(env);
        env = environmentRepository.save(env);
        env.setNamespace("env-" + env.getId().toString().replace("-", "").substring(0, 12));
        env = environmentRepository.save(env);

        // BDD-first: stocker l’URL publique dérivée (nip.io) dès la création, pour que l’UI n’attende rien.
        // Le callback pipeline peut ensuite la remplacer (env.url).
        String derivedUrl = resolveDeploymentPublicUrl(env);
        if (derivedUrl != null && !derivedUrl.isBlank()) {
            env.setUrl(derivedUrl);
            env = environmentRepository.save(env);
        }

        // Enregistrer des ressources “banales” pour alimenter le dashboard (même sans introspection K8s).
        try {
            if (derivedUrl != null && !derivedUrl.isBlank()) {
                CloudResource ingress = new CloudResource();
                ingress.setEnvironment(env);
                ingress.setResourceType(ResourceType.INGRESS);
                ingress.setResourceName(derivedUrl);
                ingress.setResourceMetadata(Map.of(
                        "namespace", env.getNamespace(),
                        "url", derivedUrl,
                        "scheme", nipScheme,
                        "masterIp", nipMasterIp,
                        "nodePort", nipNodePort
                ));
                cloudResourceRepository.save(ingress);

                CloudResource svc = new CloudResource();
                svc.setEnvironment(env);
                svc.setResourceType(ResourceType.SERVICE);
                svc.setResourceName(env.getNamespace());
                svc.setResourceMetadata(Map.of(
                        "namespace", env.getNamespace()
                ));
                cloudResourceRepository.save(svc);
            }
        } catch (Exception e) {
            log.debug("Cloud resources init ignoré: {}", e.getMessage());
        }

        // 4. Déclencher le pipeline GitLab
        Pipeline pipeline = gitLabService.triggerPipeline(
                request.getGitRepositoryUrl(),
                request.getBranch(),
                env.getId().toString(),
                app.getId(),
                app.getDockerfilePath(),
                env.getTtlHours(),
                env.getNamespace()
        );

        // 5. Enregistrer l'exécution du pipeline (relation OneToOne)
        PipelineExecution execution = new PipelineExecution();
        execution.setGitlabPipelineId(pipeline.getId());
        execution.setStatus(com.backend.devsecopsplatform_backend.entity.PipelineStatus
                .fromGitLabStatus(pipeline.getStatus() != null ? pipeline.getStatus().toString() : "running"));
        execution.setStartedAt(LocalDateTime.now());

        // 🔥 Établir la relation bidirectionnelle OneToOne
        execution.setEnvironment(env);
        env.setPipelineExecution(execution);  // Nouvelle méthode setter

        pipelineExecutionRepository.save(execution);
        environmentRepository.save(env); // Mise à jour de l'environnement avec la relation

        log.info("✅ Déploiement lancé - env: {} pipeline: {}", env.getId(), pipeline.getId());

        return DeployResponse.builder()
                .environmentId(env.getId())
                .applicationId(app.getId())
                .environmentName(env.getEnvironmentName())
                .gitlabPipelineId(pipeline.getId())
                .pipelineStatus(pipeline.getStatus().toString())
                .pipelineWebUrl(pipeline.getWebUrl())
                .message("Pipeline déclenché. Consultez le statut et les scans via l'API.")
                .build();
    }

    /**
     * Enregistre l’URL publique après déploiement (callback GitLab / job pipeline).
     */
    @Transactional
    public void publishDeploymentPublicUrl(UUID environmentId, String publicUrl) {
        EphemeralEnvironment env = environmentRepository.findById(environmentId)
                .orElseThrow(() -> new RuntimeException("Environnement introuvable: " + environmentId));
        env.setUrl(publicUrl);
        if (env.getStatus() == EnvironmentStatus.PENDING || env.getStatus() == EnvironmentStatus.BUILDING) {
            env.setStatus(EnvironmentStatus.RUNNING);
        }
        environmentRepository.save(env);
        log.info("🌐 URL déploiement enregistrée pour env {} : {}", environmentId, publicUrl);
    }

    public Optional<EnvironmentSummaryResponse> getEnvironmentById(UUID envId) {
        return environmentRepository.findById(envId)
                .map(this::toSummary);
    }

    public List<EnvironmentSummaryResponse> getMyEnvironments() {
        User user = getCurrentUser();
        List<EphemeralEnvironment> list = environmentRepository.findMyEnvironments(user);
        List<EnvironmentSummaryResponse> result = new ArrayList<>();
        for (EphemeralEnvironment e : list) {
            // 🔥 Récupération directe du pipeline associé (OneToOne)
            PipelineExecution pipeline = e.getPipelineExecution();
            result.add(EnvironmentSummaryResponse.builder()
                    .id(e.getId())
                    .environmentName(e.getEnvironmentName())
                    .gitRepositoryUrl(e.getService().getGitRepositoryUrl())
                    .gitBranch(e.getGitBranch())
                    .ttlHours(e.getTtlHours())
                    .status(e.getStatus().name())
                    .previewUrl(resolveDeploymentPublicUrl(e))
                    .createdAt(e.getCreatedAt())
                    .expiresAt(e.getExpiresAt())
                    .latestPipelineId(pipeline != null ? pipeline.getGitlabPipelineId() : null)
                    .latestPipelineStatus(pipeline != null ? pipeline.getStatus().name() : null)
                    .build());
        }
        return result;
    }

    /** Environnements de l’utilisateur, filtrés par application (pour le sélecteur d’env du dashboard). */
    public List<EnvironmentSummaryResponse> getMyEnvironmentsForApplication(UUID appId) {
        User user = getCurrentUser();
        List<EphemeralEnvironment> list = environmentRepository
                .findByRequestedByAndServiceIdWithServiceAndPipelineOrderByCreatedAtDesc(user, appId);
        List<EnvironmentSummaryResponse> result = new ArrayList<>();
        for (EphemeralEnvironment e : list) {
            PipelineExecution pipeline = e.getPipelineExecution();
            result.add(EnvironmentSummaryResponse.builder()
                    .id(e.getId())
                    .environmentName(e.getEnvironmentName())
                    .gitRepositoryUrl(e.getService().getGitRepositoryUrl())
                    .gitBranch(e.getGitBranch())
                    .ttlHours(e.getTtlHours())
                    .status(e.getStatus().name())
                    .previewUrl(resolveDeploymentPublicUrl(e))
                    .createdAt(e.getCreatedAt())
                    .expiresAt(e.getExpiresAt())
                    .latestPipelineId(pipeline != null ? pipeline.getGitlabPipelineId() : null)
                    .latestPipelineStatus(pipeline != null ? pipeline.getStatus().name() : null)
                    .build());
        }
        return result;
    }

    public Optional<EnvironmentSummaryResponse> getEnvironment(UUID envId) {
        User user = getCurrentUser();
        return environmentRepository.findByIdAndRequestedBy(envId, user)
                .map(this::toSummary);
    }

    public PipelineScanResponse getPipelineAndScan(UUID envId) {
        User user = getCurrentUser();
        EphemeralEnvironment env = environmentRepository.findByIdAndRequestedBy(envId, user)
                .orElseThrow(() -> new RuntimeException("Environnement non trouvé"));

        // 🔥 Récupération directe du pipeline (OneToOne)
        PipelineExecution latest = env.getPipelineExecution();
        if (latest == null) {
            throw new RuntimeException("Aucun pipeline pour cet environnement");
        }

        Long pipelineId = latest.getGitlabPipelineId();
        if (pipelineId == null || pipelineId <= 0) {
            throw new RuntimeException("ID pipeline GitLab invalide");
        }
        try {
            Map<String, Object> summary = gitLabService.getPipelineSummary(pipelineId);
            pipelineStageSyncService.syncStagesForPipeline(pipelineId);
            Map<String, JsonNode> reports = gitLabService.getAllSecurityReports(pipelineId);
            return PipelineScanResponse.builder()
                    .pipelineId(pipelineId)
                    .status((String) summary.get("status"))
                    .webUrl((String) summary.get("webUrl"))
                    .jobStatusCount(summary.get("jobStatusCount"))
                    .jobs(summary.get("jobs"))
                    .securityReports(reports)
                    .dataSource("gitlab")
                    .build();
        } catch (Exception e) {
            log.warn("Erreur récupération pipeline GitLab {}: {}, fallback BDD (stages_json)", pipelineId, e.getMessage());
            Object jobs = latest.getStagesJson() != null
                    ? pipelineStageSyncService.getJobsFromStagesJson(latest)
                    : List.<Map<String, Object>>of();
            Object jobStatusCount = latest.getStagesJson() != null
                    ? pipelineStageSyncService.getJobStatusCountFromStagesJson(latest)
                    : Map.of(latest.getStatus().name(), 1L);
            if (jobStatusCount instanceof Map && ((Map<?, ?>) jobStatusCount).isEmpty()) {
                jobStatusCount = Map.of(latest.getStatus().name(), 1L);
            }
            return PipelineScanResponse.builder()
                    .pipelineId(pipelineId)
                    .status(latest.getStatus().name())
                    .webUrl(latest.getStagesJson() != null ? (String) latest.getStagesJson().get("webUrl") : null)
                    .jobStatusCount(jobStatusCount)
                    .jobs(jobs)
                    .securityReports(Map.of())
                    .dataSource("database")
                    .build();
        }
    }

    public SecuritySummaryResponse getSecuritySummary(UUID envId) {
        User user = getCurrentUser();
        EphemeralEnvironment env = environmentRepository.findByIdAndRequestedBy(envId, user)
                .orElseThrow(() -> new RuntimeException("Environnement non trouvé"));

        // 🔥 Récupération directe du pipeline
        PipelineExecution latest = env.getPipelineExecution();
        if (latest == null) {
            throw new RuntimeException("Aucun pipeline pour cet environnement");
        }

        Long pipelineId = latest.getGitlabPipelineId();
        if (pipelineId == null || pipelineId <= 0) {
            throw new RuntimeException("ID pipeline GitLab invalide");
        }

        Map<String, JsonNode> reports = gitLabService.getAllSecurityReports(pipelineId);

        int[] counters = new int[5];
        for (JsonNode report : reports.values()) {
            accumulateVulnerabilities(report, counters);
        }

        return SecuritySummaryResponse.builder()
                .environmentId(env.getId())
                .environmentName(env.getEnvironmentName())
                .pipelineId(pipelineId)
                .pipelineStatus(latest.getStatus().name())
                .critical(counters[0])
                .high(counters[1])
                .medium(counters[2])
                .low(counters[3])
                .info(counters[4])
                .build();
    }

    private void accumulateVulnerabilities(JsonNode report, int[] counters) {
        if (report == null || report.isNull()) {
            return;
        }

        if (report.has("vulnerabilities") && report.get("vulnerabilities").isArray()) {
            addFromArray(report.get("vulnerabilities"), "severity", counters);
        }

        if (report.has("Vulnerabilities") && report.get("Vulnerabilities").isArray()) {
            addFromArray(report.get("Vulnerabilities"), "Severity", counters);
        }

        if (report.has("results") && report.get("results").isArray()) {
            for (JsonNode result : report.get("results")) {
                if (result.has("Vulnerabilities") && result.get("Vulnerabilities").isArray()) {
                    addFromArray(result.get("Vulnerabilities"), "Severity", counters);
                }
            }
        }
    }

    private void addFromArray(JsonNode arrayNode, String severityField, int[] counters) {
        for (JsonNode v : arrayNode) {
            String sev = v.path(severityField).asText(null);
            if (sev == null) continue;
            switch (sev.toUpperCase()) {
                case "CRITICAL" -> counters[0]++;
                case "HIGH" -> counters[1]++;
                case "MEDIUM" -> counters[2]++;
                case "LOW" -> counters[3]++;
                case "INFO" -> counters[4]++;
                default -> {}
            }
        }
    }

    private EnvironmentSummaryResponse toSummary(EphemeralEnvironment e) {
        // 🔥 Récupération directe du pipeline
        PipelineExecution pipeline = e.getPipelineExecution();
        return EnvironmentSummaryResponse.builder()
                .id(e.getId())
                .environmentName(e.getEnvironmentName())
                .gitRepositoryUrl(e.getService().getGitRepositoryUrl())
                .gitBranch(e.getGitBranch())
                .ttlHours(e.getTtlHours())
                .status(e.getStatus().name())
                .previewUrl(resolveDeploymentPublicUrl(e))
                .createdAt(e.getCreatedAt())
                .expiresAt(e.getExpiresAt())
                .latestPipelineId(pipeline != null ? pipeline.getGitlabPipelineId() : null)
                .latestPipelineStatus(pipeline != null ? pipeline.getStatus().name() : null)
                .build();
    }

    private User getCurrentUser() {
        return Optional.ofNullable(org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication())
                .map(auth -> userRepository.findByUsername(auth.getName()).orElse(null))
                .orElseThrow(() -> new RuntimeException("Utilisateur non authentifié"));
    }
}