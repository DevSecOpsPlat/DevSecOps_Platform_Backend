package com.backend.devsecopsplatform_backend.service.environment;

import com.backend.devsecopsplatform_backend.controller.environment.*;
import com.backend.devsecopsplatform_backend.entity.*;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.service.application.ApplicationService;
import com.backend.devsecopsplatform_backend.service.EncryptionService;
import com.backend.devsecopsplatform_backend.service.GitHubValidationService;
import com.backend.devsecopsplatform_backend.service.GitLabService;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.gitlab4j.api.models.Pipeline;
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

    /**
     * Déploiement : crée ou réutilise une application, crée l'environnement, déclenche le pipeline.
     * Le token GitHub est chiffré en BDD.
     */
    @Transactional
    public DeployResponse deploy(DeployRequest request) {
        User currentUser = getCurrentUser();

        // Log des données reçues (pour vérifier le clonage) — token non affiché en clair
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

        // 2. Trouver ou créer l'application (token chiffré, dockerfilePath)
        String dockerfilePath = request.getDockerfilePath() != null && !request.getDockerfilePath().isBlank()
                ? request.getDockerfilePath() : "./Dockerfile";
        com.backend.devsecopsplatform_backend.entity.Application app = applicationService
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
        env.setApplication(app);
        env.setGitBranch(request.getBranch());
        env.setRequestedBy(currentUser);
        env.setStatus(EnvironmentStatus.PENDING);
        env.setTtlHours(ttlHours);
        app.addEphemeralEnvironment(env);
        env = environmentRepository.save(env);
        env.setNamespace("env-" + env.getId().toString().replace("-", "").substring(0, 12));
        env = environmentRepository.save(env);

        // 4. Déclencher le pipeline GitLab (token déchiffré, variables: GIT_REPO_URL, GIT_BRANCH, GITHUB_TOKEN, DOCKERFILE_PATH)
        Pipeline pipeline = gitLabService.triggerPipeline(
                request.getGitRepositoryUrl(),
                request.getBranch(),
                env.getId().toString(),
                app.getId(),
                app.getDockerfilePath()
        );

        // 5. Enregistrer l'exécution du pipeline
        PipelineExecution execution = new PipelineExecution();
        execution.setEnvironment(env);
        execution.setGitlabPipelineId(pipeline.getId().intValue());
        execution.setStatus(com.backend.devsecopsplatform_backend.entity.PipelineStatus
                .fromGitLabStatus(pipeline.getStatus() != null ? pipeline.getStatus().toString() : "running"));
        execution.setStartedAt(LocalDateTime.now());
        env.addPipelineExecution(execution);
        pipelineExecutionRepository.save(execution);

        log.info("✅ Déploiement lancé - env: {} pipeline: {}", env.getId(), pipeline.getId());

        return DeployResponse.builder()
                .environmentId(env.getId())
                .environmentName(env.getEnvironmentName())
                .gitlabPipelineId(pipeline.getId().intValue())
                .pipelineStatus(pipeline.getStatus().toString())
                .pipelineWebUrl(pipeline.getWebUrl())
                .message("Pipeline déclenché. Consultez le statut et les scans via l'API.")
                .build();
    }

    public List<EnvironmentSummaryResponse> getMyEnvironments() {
        User user = getCurrentUser();
        List<EphemeralEnvironment> list = environmentRepository.findMyEnvironments(user);
        List<EnvironmentSummaryResponse> result = new ArrayList<>();
        for (EphemeralEnvironment e : list) {
            PipelineExecution latest = pipelineExecutionRepository.findFirstByEnvironmentOrderByCreatedAtDesc(e).orElse(null);
            result.add(EnvironmentSummaryResponse.builder()
                    .id(e.getId())
                    .environmentName(e.getEnvironmentName())
                    .gitRepositoryUrl(e.getApplication().getGitRepositoryUrl())
                    .gitBranch(e.getGitBranch())
                    .ttlHours(e.getTtlHours())
                    .status(e.getStatus().name())
                    .createdAt(e.getCreatedAt())
                    .expiresAt(e.getExpiresAt())
                    .latestPipelineId(latest != null ? latest.getGitlabPipelineId() : null)
                    .latestPipelineStatus(latest != null ? latest.getStatus().name() : null)
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
        PipelineExecution latest = pipelineExecutionRepository.findFirstByEnvironmentOrderByCreatedAtDesc(env)
                .orElseThrow(() -> new RuntimeException("Aucun pipeline pour cet environnement"));
        Integer pipelineId = latest.getGitlabPipelineId();
        if (pipelineId == null) {
            throw new RuntimeException("ID pipeline GitLab manquant");
        }
        Map<String, Object> summary = gitLabService.getPipelineSummary(pipelineId.longValue());
        Map<String, JsonNode> reports = gitLabService.getAllSecurityReports(pipelineId.longValue());
        return PipelineScanResponse.builder()
                .pipelineId(pipelineId)
                .status((String) summary.get("status"))
                .webUrl((String) summary.get("webUrl"))
                .jobStatusCount(summary.get("jobStatusCount"))
                .jobs(summary.get("jobs"))
                .securityReports(reports)
                .build();
    }

    private EnvironmentSummaryResponse toSummary(EphemeralEnvironment e) {
        PipelineExecution latest = pipelineExecutionRepository.findFirstByEnvironmentOrderByCreatedAtDesc(e).orElse(null);
        return EnvironmentSummaryResponse.builder()
                .id(e.getId())
                .environmentName(e.getEnvironmentName())
                .gitRepositoryUrl(e.getApplication().getGitRepositoryUrl())
                .gitBranch(e.getGitBranch())
                .ttlHours(e.getTtlHours())
                .status(e.getStatus().name())
                .createdAt(e.getCreatedAt())
                .expiresAt(e.getExpiresAt())
                .latestPipelineId(latest != null ? latest.getGitlabPipelineId() : null)
                .latestPipelineStatus(latest != null ? latest.getStatus().name() : null)
                .build();
    }

    private User getCurrentUser() {
        return Optional.ofNullable(org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication())
                .map(auth -> userRepository.findByUsername(auth.getName()).orElse(null))
                .orElseThrow(() -> new RuntimeException("Utilisateur non authentifié"));
    }
}
