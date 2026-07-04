package com.backend.devsecopsplatform_backend.service.qualitygate;

import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.PipelineStatus;
import com.backend.devsecopsplatform_backend.entity.QualityGateSnapshot;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.AppServiceRepository;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.repository.FindingOccurrenceRepository;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.repository.QualityGateSnapshotRepository;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.service.AiAnalysisService;
import com.backend.devsecopsplatform_backend.service.GitLabService;
import com.backend.devsecopsplatform_backend.service.SonarBranchResolution;
import com.backend.devsecopsplatform_backend.service.defectdojo.DefectDojoService;
import com.backend.devsecopsplatform_backend.service.defectdojo.dto.DefectDojoDashboard2Response;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.HardGateViolationDto;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.QualityGateEnvironmentOptionDto;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.QualityGateResultDto;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.QualityGateSnapshotHistoryItemDto;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.QualityGateStageDto;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.QualityGateToolMetricDto;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.SecurityGateIngestRequest;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.SecurityScoreDto;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.SoftwareQualityDimensionDto;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.SonarAvailabilityDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.time.Instant;
import java.util.*;
import java.util.function.Supplier;

@Service
@Slf4j
@RequiredArgsConstructor
public class QualityGateService {

    private static final List<String> STAGE_ORDER = List.of(
            "setup", "clone", "code-analysis", "sonarqube-setup", "sonarqube-scan",
            "sca", "sca-trivy", "sast", "secrets", "secrets-iac", "iac", "build",
            "build-image", "container-scan", "push-image", "deploy-k8s", "zap-scan",
            "reporting", "aggregate-report", "import-defectdojo", "security-validation"
    );

    private static final int SNAPSHOT_HISTORY_MAX = 20;

    private static final Map<String, List<String>> TOOL_STAGE_MATCHERS = Map.of(
            "trivy", List.of("sca-trivy", "sca"),
            "semgrep", List.of("sast", "semgrep"),
            "gitleaks", List.of("gitleaks", "secrets"),
            "grype", List.of("container-scan", "container", "grype"),
            "checkov", List.of("secrets-iac", "iac", "checkov"),
            "zap", List.of("zap-scan", "zap", "dast"),
            "hadolint", List.of("hadolint"),
            "sonarqube", List.of("sonarqube-scan", "code-analysis", "sonar")
    );

    private static final Set<String> CASCADE_AFTER_BLOCK = Set.of(
            "push-image", "deploy-k8s", "zap-scan", "import-defectdojo"
    );

    public static final String SNAPSHOT_SOURCE_PIPELINE_SYNC = "PIPELINE_SYNC";
    public static final String SNAPSHOT_SOURCE_PIPELINE_DD = "DEFECTDOJO_IMPORT";
    public static final String SNAPSHOT_SOURCE_CI_INGEST = "CI_INGEST";
    public static final String SNAPSHOT_SOURCE_STAGES_SYNC = "STAGES_SYNC";
    public static final String SNAPSHOT_SOURCE_MANUAL = "MANUAL";

    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final FindingOccurrenceRepository findingOccurrenceRepository;
    private final EphemeralEnvironmentRepository environmentRepository;
    private final AppServiceRepository applicationRepository;
    private final UserRepository userRepository;
    private final GitLabService gitLabService;
    private final DefectDojoService defectDojoService;
    private final AiAnalysisService aiAnalysisService;
    private final SecurityScoringService securityScoringService;
    private final QualityGateSnapshotRepository qualityGateSnapshotRepository;
    private final ObjectMapper objectMapper;

    @Transactional
    public void ingestFromPipeline(SecurityGateIngestRequest request) {
        if (request.getEnvironmentId() == null) {
            throw new IllegalArgumentException("environment_id requis");
        }
        EphemeralEnvironment env = environmentRepository.findById(request.getEnvironmentId())
                .orElseThrow(() -> new IllegalArgumentException("Environnement introuvable"));

        PipelineExecution execution = pipelineExecutionRepository
                .findFirstByEnvironmentOrderByCreatedAtDesc(env)
                .orElse(null);
        if (execution == null) {
            log.warn("Aucune exécution pipeline pour env {}", request.getEnvironmentId());
            return;
        }

        Map<String, Object> previousGate = execution.getQualityGateJson();
        Map<String, Object> gate = new LinkedHashMap<>();
        if (previousGate != null && previousGate.get("snapshotHistory") instanceof List<?> hist) {
            gate.put("snapshotHistory", new ArrayList<>(hist));
        }
        if (previousGate != null && previousGate.get("displaySnapshot") != null) {
            appendSnapshotHistoryEntry(gate, previousGate);
        }
        gate.put("recommendation", request.getRecommendation());
        gate.put("verdict", mapVerdict(request.getRecommendation()));
        gate.put("pipelineId", request.getPipelineId());
        gate.put("evaluatedAt", Instant.now().toString());
        gate.put("critical", request.getCritical());
        gate.put("high", request.getHigh());
        gate.put("secrets", request.getSecrets());
        gate.put("containerCritical", request.getContainerCritical());
        if (request.getContainerHigh() != null) {
            gate.put("containerHigh", request.getContainerHigh());
        }
        if (request.getScaMedium() != null) {
            gate.put("scaMedium", request.getScaMedium());
        }
        if (request.getSemgrepHigh() != null) {
            gate.put("semgrepHigh", request.getSemgrepHigh());
        }
        if (request.getSemgrepMedium() != null) {
            gate.put("semgrepMedium", request.getSemgrepMedium());
        }
        if (request.getCheckovFailed() != null) {
            gate.put("checkovFailed", request.getCheckovFailed());
        }
        gate.put("dastHigh", request.getDastHigh());
        if (request.getSonarNcloc() != null && request.getSonarNcloc() > 0) {
            gate.put("sonarNcloc", request.getSonarNcloc());
        }
        if (request.getSonarQualityGate() != null && !request.getSonarQualityGate().isBlank()) {
            gate.put("sonarQualityGate", request.getSonarQualityGate().trim());
        }
        if (request.getSonarBlockers() != null) {
            gate.put("sonarBlockers", request.getSonarBlockers());
        }
        if (request.getSonarCriticals() != null) {
            gate.put("sonarCriticals", request.getSonarCriticals());
        }
        if (request.getSonarBugs() != null) {
            gate.put("sonarBugs", request.getSonarBugs());
        }
        if (request.getSonarVulnerabilities() != null) {
            gate.put("sonarVulnerabilities", request.getSonarVulnerabilities());
        }
        if (request.getSonarHotspots() != null) {
            gate.put("sonarHotspots", request.getSonarHotspots());
        }
        if (request.getSonarSecurityRating() != null && !request.getSonarSecurityRating().isBlank()) {
            gate.put("sonarSecurityRating", request.getSonarSecurityRating().trim());
        }
        Map<String, Object> summaryPayload = synthesizeSummaryFromIngest(request);
        if (!summaryPayload.isEmpty()) {
            gate.put("summary", summaryPayload);
            persistSonarSqFieldsOnGate(gate, summaryPayload);
        }
        if (request.getQualityGate() != null) {
            gate.put("qualityGate", objectMapper.convertValue(request.getQualityGate(), Map.class));
        }

        execution.setQualityGateJson(gate);
        pipelineExecutionRepository.save(execution);
        log.info("Quality gate enregistré pour env {} pipeline {} (summary={})",
                request.getEnvironmentId(), request.getPipelineId(), !summaryPayload.isEmpty());
    }

    @Transactional
    public void refreshSnapshotForEnvironment(UUID applicationId, UUID environmentId) {
        User user = currentUser();
        applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));
        EphemeralEnvironment env = environmentRepository.findByIdWithService(environmentId)
                .orElseThrow(() -> new IllegalArgumentException("Environnement introuvable"));
        if (env.getService() == null || !applicationId.equals(env.getService().getId())) {
            throw new IllegalArgumentException("Environnement introuvable pour cette application");
        }
        PipelineExecution execution = pipelineExecutionRepository
                .findByEnvironmentIdAndApplicationId(environmentId, applicationId)
                .orElseThrow(() -> new IllegalArgumentException("Aucune exécution pipeline pour cet environnement"));
        buildAndPersistSnapshot(env.getService(), env.getGitBranch(), execution, false, SNAPSHOT_SOURCE_MANUAL);
    }

    /**
     * Capture API explicite (sans webhook) : force l'écriture du snapshot en base
     * pour l'environnement donné. Appel authentifié → DefectDojo se remplit.
     */
    @Transactional
    public QualityGateResultDto captureSnapshotViaApi(UUID applicationId, UUID environmentId) {
        User user = currentUser();
        applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));
        EphemeralEnvironment env = environmentRepository.findByIdWithService(environmentId)
                .orElseThrow(() -> new IllegalArgumentException("Environnement introuvable"));
        if (env.getService() == null || !applicationId.equals(env.getService().getId())) {
            throw new IllegalArgumentException("Environnement introuvable pour cette application");
        }
        PipelineExecution execution = pipelineExecutionRepository
                .findByEnvironmentIdAndApplicationId(environmentId, applicationId)
                .orElseThrow(() -> new IllegalArgumentException("Aucune exécution pipeline pour cet environnement"));

        if (!canPersistSnapshot(execution)) {
            throw new SnapshotCaptureRejectedException(
                    "Capture impossible — attendez la fin du job security-validation ou la fin du pipeline.");
        }

        buildAndPersistSnapshot(env.getService(), env.getGitBranch(), execution, false, SNAPSHOT_SOURCE_MANUAL);

        QualityGateSnapshot saved = qualityGateSnapshotRepository
                .findByPipelineExecutionId(execution.getId())
                .orElseThrow(() -> new IllegalStateException("Snapshot non enregistré après capture"));
        return fromSnapshotEntity(saved);
    }

    /**
     * Capture déclenchée par le job CI security-validation (secret partagé, sans JWT).
     * Charge les associations User dans la transaction avant impersonation DefectDojo.
     */
    @Transactional
    public QualityGateResultDto captureSnapshotFromPipeline(UUID environmentId) {
        PipelineExecution execution = pipelineExecutionRepository
                .findByEnvironmentIdWithDetails(environmentId)
                .orElseThrow(() -> new IllegalArgumentException("Pipeline introuvable"));
        AppService app = execution.getEnvironment().getService();
        if (app == null) {
            throw new IllegalArgumentException("Application manquante");
        }

        String username = resolveSnapshotUsername(app, execution);
        try {
            if (username != null) {
                SecurityContextHolder.getContext().setAuthentication(
                        new UsernamePasswordAuthenticationToken(username, null, List.of()));
            }
            buildAndPersistSnapshot(
                    app,
                    execution.getEnvironment().getGitBranch(),
                    execution,
                    true,
                    SNAPSHOT_SOURCE_PIPELINE_SYNC);

            QualityGateSnapshot saved = qualityGateSnapshotRepository
                    .findByPipelineExecutionId(execution.getId())
                    .orElseThrow(() -> new IllegalStateException("Snapshot non enregistré après capture"));
            return fromSnapshotEntity(saved);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    /**
     * Capture un snapshot backend (Sonar + DefectDojo tag env-* + stages GitLab).
     * Ne dépend pas du rapport CI security-validation.
     */
    @Transactional
    public void captureSnapshotAfterPipeline(PipelineExecution execution) {
        captureSnapshotAfterPipeline(execution, SNAPSHOT_SOURCE_PIPELINE_SYNC, false);
    }

    /** Après le job import-defectdojo — met à jour le snapshot même s'il existe déjà. */
    @Transactional
    public void captureSnapshotAfterDefectDojoImport(PipelineExecution execution) {
        captureSnapshotAfterPipeline(execution, SNAPSHOT_SOURCE_PIPELINE_DD, true);
    }

    /** Capture une seule fois si aucune ligne n'existe pour cette exécution pipeline. */
    @Transactional
    public void captureSnapshotIfAbsent(PipelineExecution execution) {
        captureSnapshotAfterPipeline(execution, SNAPSHOT_SOURCE_PIPELINE_SYNC, false);
    }

    /**
     * Re-capture après synchro GitLab → stages_json.jobs peuplé.
     * Corrige les snapshots pris trop tôt par le job CI (security-validation) quand jobs était vide.
     */
    @Transactional
    public void captureSnapshotAfterStagesSync(PipelineExecution execution) {
        if (execution == null || execution.getId() == null) {
            return;
        }
        PipelineExecution loaded = pipelineExecutionRepository.findById(execution.getId()).orElse(execution);
        int jobCount = countJobsInStagesJson(loaded);
        PipelineStatus status = loaded.getStatus();
        if (status == null || !status.isFinished()) {
            return;
        }
        if (jobCount <= 0) {
            captureSnapshotIfAbsent(loaded);
            return;
        }
        captureSnapshotAfterPipeline(loaded, SNAPSHOT_SOURCE_STAGES_SYNC, true);
    }

    private int countJobsInStagesJson(PipelineExecution execution) {
        return getJobsFromStagesJson(execution).size();
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onPipelineArtifactsIngested(PipelineArtifactsIngestedEvent event) {
        if (event == null || event.pipelineExecutionId() == null) {
            return;
        }
        try {
            pipelineExecutionRepository.findById(event.pipelineExecutionId())
                    .ifPresent(this::captureSnapshotAfterDefectDojoImport);
        } catch (Exception e) {
            log.warn("Snapshot QG après ingestion ignoré (execId={}): {}",
                    event.pipelineExecutionId(), e.getMessage());
        }
    }

    @Transactional
    public int backfillMissingSnapshots(UUID applicationId) {
        User user = currentUser();
        applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));
        int created = 0;
        for (EphemeralEnvironment env : environmentRepository.findByServiceWithPipeline(applicationId, null)) {
            PipelineExecution pe = env.getPipelineExecution();
            if (pe == null || pe.getStatus() == null || !pe.getStatus().isFinished()) {
                continue;
            }
            if (qualityGateSnapshotRepository.findByPipelineExecutionId(pe.getId()).isPresent()) {
                continue;
            }
            try {
                captureSnapshotAfterPipeline(pe, SNAPSHOT_SOURCE_MANUAL, false);
                created++;
            } catch (Exception e) {
                log.warn("Backfill snapshot échoué pour exec {}: {}", pe.getId(), e.getMessage());
            }
        }
        return created;
    }

    private void captureSnapshotAfterPipeline(PipelineExecution execution, String source, boolean forceUpdate) {
        if (execution == null || execution.getId() == null) {
            return;
        }
        if (!forceUpdate && qualityGateSnapshotRepository.findByPipelineExecutionId(execution.getId()).isPresent()) {
            return;
        }
        PipelineExecution loaded = pipelineExecutionRepository
                .findByIdWithEnvironmentAndService(execution.getId())
                .orElse(execution);
        if (loaded.getEnvironment() == null || loaded.getEnvironment().getService() == null) {
            log.debug("Snapshot QG ignoré : environnement ou application manquant pour exec {}", loaded.getId());
            return;
        }
        try {
            buildAndPersistSnapshot(
                    loaded.getEnvironment().getService(),
                    loaded.getEnvironment().getGitBranch(),
                    loaded,
                    false,
                    source);
            log.info("Snapshot QG enregistré (table={}, force={}) pipeline exec {} env {}",
                    source, forceUpdate, loaded.getId(), loaded.getEnvironment().getId());
        } catch (Exception e) {
            log.warn("Snapshot QG pipeline non enregistré pour exec {}: {}", loaded.getId(), e.getMessage());
        }
    }

    @Transactional(readOnly = true)
    public QualityGateResultDto getForApplication(UUID applicationId, String branch) {
        return getForApplication(applicationId, branch, null);
    }

    @Transactional(readOnly = true)
    public QualityGateResultDto getForApplication(UUID applicationId, String branch, UUID environmentId) {
        return getForApplication(applicationId, branch, environmentId, false);
    }

    @Transactional(readOnly = true)
    public QualityGateResultDto getForApplication(
            UUID applicationId,
            String branch,
            UUID environmentId,
            boolean refresh
    ) {
        return getForApplication(applicationId, branch, environmentId, refresh, null);
    }

    @Transactional(readOnly = true)
    public QualityGateResultDto getForApplication(
            UUID applicationId,
            String branch,
            UUID environmentId,
            boolean refresh,
            UUID snapshotId
    ) {
        User user = currentUser();
        AppService app = applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));

        if (snapshotId != null) {
            return getSnapshotById(applicationId, snapshotId);
        }

        String effectiveBranch = normalizeBranch(branch);
        PipelineExecution execution;

        if (environmentId != null) {
            environmentRepository.findByIdAndService_Id(environmentId, applicationId)
                    .orElseThrow(() -> new IllegalArgumentException("Environnement introuvable pour cette application"));
            execution = pipelineExecutionRepository
                    .findByEnvironmentIdAndApplicationId(environmentId, applicationId)
                    .orElse(null);
            if (execution != null && execution.getEnvironment() != null) {
                effectiveBranch = execution.getEnvironment().getGitBranch();
            }
            if (!refresh) {
                QualityGateResultDto stored = loadSnapshotForEnvironment(environmentId, execution);
                if (stored != null) {
                    finalizeDefectDojoPresentation(stored, app, effectiveBranch, environmentId, execution);
                    return stored;
                }
                return buildMissingSnapshotResult(app, effectiveBranch, environmentId, execution);
            }
        } else {
            execution = findLatestExecution(applicationId, effectiveBranch);
            if (!refresh) {
                QualityGateResultDto stored = tryLoadSnapshotFromDb(applicationId, effectiveBranch, execution);
                if (stored != null) {
                    UUID envId = environmentId != null ? environmentId
                            : (execution != null && execution.getEnvironment() != null
                                    ? execution.getEnvironment().getId() : null);
                    finalizeDefectDojoPresentation(stored, app, effectiveBranch, envId, execution);
                    return stored;
                }
                return buildMissingSnapshotResultForBranch(app, effectiveBranch, execution);
            }
        }

        // refresh=true uniquement : reconstruction live (DefectDojo + SonarQube), sans écriture BDD
        if (environmentId != null) {
            execution = pipelineExecutionRepository
                    .findByEnvironmentIdAndApplicationId(environmentId, applicationId)
                    .orElse(execution);
        }
        UUID effectiveEnvironmentId = environmentId;
        DefectDojoDashboard2Response dd = null;
        try {
            dd = defectDojoService.getDashboard2(applicationId, effectiveBranch, effectiveEnvironmentId);
        } catch (Exception e) {
            log.warn("DefectDojo indisponible pour quality gate: {}", e.getMessage());
        }

        Map<String, Object> sonar = fetchSonarForQualityGate(app, effectiveBranch, execution);
        QualityGateResultDto live = buildResult(app, effectiveBranch, execution, dd, sonar, effectiveEnvironmentId);
        return annotateLiveRefreshResult(live, execution);
    }

    /** Indique si un snapshot peut être figé en BDD pour cette exécution. */
    public boolean canPersistSnapshot(PipelineExecution execution) {
        if (execution == null) {
            return false;
        }
        if (securityValidationJobState(execution) == SecurityValidationJobState.SUCCESS) {
            return true;
        }
        PipelineStatus status = execution.getStatus();
        return status != null && status.isFinished();
    }

    private QualityGateResultDto annotateLiveRefreshResult(QualityGateResultDto result, PipelineExecution execution) {
        if (result == null) {
            return null;
        }
        result.setFromSnapshot(false);
        boolean captureAllowed = canPersistSnapshot(execution);
        result.setCanCaptureSnapshot(captureAllowed);
        if (execution == null) {
            return result;
        }
        boolean running = execution.getStatus() != null && !execution.getStatus().isFinished();
        if (running && !captureAllowed) {
            result.setVerdictSource("PIPELINE_IN_PROGRESS");
            result.setSummary("Pipeline"
                    + (execution.getGitlabPipelineId() != null ? " #" + execution.getGitlabPipelineId() : "")
                    + " en cours — affichage live, snapshot non figé.");
            result.setIncompleteRecommendationMessage(
                    "Pipeline en cours — affichage live, snapshot non figé.");
            result.setSecurityScore(null);
        }
        return result;
    }

    /**
     * Historique des snapshots conservés en BDD pour une branche (un enregistrement par pipeline / environnement).
     * Les données live DefectDojo/Sonar peuvent être écrasées — ces lignes restent figées.
     */
    @Transactional(readOnly = true)
    public List<QualityGateSnapshotHistoryItemDto> listSnapshotHistory(
            UUID applicationId,
            String branch,
            UUID environmentId
    ) {
        User user = currentUser();
        applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));

        List<QualityGateSnapshot> rows;
        if (environmentId != null) {
            environmentRepository.findByIdAndService_Id(environmentId, applicationId)
                    .orElseThrow(() -> new IllegalArgumentException("Environnement introuvable pour cette application"));
            rows = qualityGateSnapshotRepository.findAllByEnvironmentIdOrderByCreatedAtDesc(environmentId);
        } else {
            String effectiveBranch = normalizeBranch(branch);
            if (effectiveBranch == null) {
                return List.of();
            }
            rows = qualityGateSnapshotRepository
                    .findAllByApplicationIdAndBranchOrderByCreatedAtDesc(applicationId, effectiveBranch);
        }

        List<QualityGateSnapshotHistoryItemDto> out = new ArrayList<>();
        for (QualityGateSnapshot row : rows) {
            out.add(toHistoryItem(row));
        }
        return out;
    }

    @Transactional(readOnly = true)
    public QualityGateResultDto getSnapshotById(UUID applicationId, UUID snapshotId) {
        User user = currentUser();
        AppService app = applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));

        QualityGateSnapshot row = qualityGateSnapshotRepository.findById(snapshotId)
                .orElseThrow(() -> new IllegalArgumentException("Snapshot introuvable"));
        if (!applicationId.equals(row.getApplicationId())) {
            throw new IllegalArgumentException("Snapshot introuvable pour cette application");
        }
        QualityGateResultDto dto = fromSnapshotEntity(row);
        if (dto == null) {
            throw new IllegalArgumentException("Snapshot illisible");
        }
        PipelineExecution execution = row.getEnvironmentId() != null
                ? pipelineExecutionRepository
                        .findByEnvironmentIdAndApplicationId(row.getEnvironmentId(), applicationId)
                        .orElse(null)
                : null;
        if (execution != null) {
            enrichWithPipelineRuntimeState(dto, execution);
        }
        finalizeDefectDojoPresentation(dto, app, dto.getBranch(), row.getEnvironmentId(), execution);
        return dto;
    }

    @Transactional(readOnly = true)
    public List<QualityGateEnvironmentOptionDto> listEnvironments(UUID applicationId, String branch) {
        User user = currentUser();
        applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));

        String effectiveBranch = normalizeBranch(branch);
        List<EphemeralEnvironment> envs = environmentRepository.findByServiceWithPipeline(
                applicationId, effectiveBranch);

        List<QualityGateEnvironmentOptionDto> options = new ArrayList<>();
        for (EphemeralEnvironment env : envs) {
            PipelineExecution pe = env.getPipelineExecution();
            Map<String, Object> gate = pe != null ? pe.getQualityGateJson() : null;
            Optional<QualityGateSnapshot> tableSnap = qualityGateSnapshotRepository
                    .findFirstByEnvironmentIdOrderByCreatedAtDesc(env.getId());
            Instant evaluatedAt = tableSnap.map(QualityGateSnapshot::getEvaluatedAt).orElse(null);
            if (evaluatedAt == null) {
                evaluatedAt = parseInstant(gate != null ? gate.get("evaluatedAt") : null);
            }
            Instant snapshotSavedAt = tableSnap.map(QualityGateSnapshot::getCreatedAt).orElse(null);
            if (snapshotSavedAt == null) {
                snapshotSavedAt = parseInstant(gate != null ? gate.get("snapshotSavedAt") : null);
            }
            boolean hasSnapshot = tableSnap.isPresent()
                    || (gate != null && gate.get("displaySnapshot") != null);
            options.add(QualityGateEnvironmentOptionDto.builder()
                    .environmentId(env.getId())
                    .environmentName(env.getEnvironmentName())
                    .branch(env.getGitBranch())
                    .status(env.getStatus() != null ? env.getStatus().name() : null)
                    .pipelineId(pe != null && pe.getGitlabPipelineId() != null
                            ? String.valueOf(pe.getGitlabPipelineId())
                            : tableSnap.map(s -> s.getGitlabPipelineId() != null
                                    ? String.valueOf(s.getGitlabPipelineId()) : null).orElse(null))
                    .pipelineStatus(pe != null && pe.getStatus() != null ? pe.getStatus().name() : null)
                    .evaluatedAt(evaluatedAt)
                    .snapshotSavedAt(snapshotSavedAt)
                    .snapshotId(tableSnap.map(QualityGateSnapshot::getId).orElse(null))
                    .snapshotSource(tableSnap.map(QualityGateSnapshot::getSource).orElse(null))
                    .verdict(tableSnap.map(s -> extractVerdictFromPayload(s.getPayload())).orElse(null))
                    .hasSnapshot(hasSnapshot)
                    .build());
        }
        return options;
    }

    private void buildAndPersistSnapshot(
            AppService app,
            String branch,
            PipelineExecution execution,
            boolean appendHistory,
            String source
    ) {
        if (execution == null || execution.getEnvironment() == null) {
            throw new IllegalStateException("Pipeline execution ou environnement manquant pour snapshot");
        }
        UUID environmentId = execution.getEnvironment().getId();
        DefectDojoDashboard2Response dd = fetchDefectDojoForSnapshot(app, execution, branch, environmentId);
        Map<String, Object> sonar = fetchSonarForQualityGate(app, branch, execution);
        QualityGateResultDto result = buildResult(app, branch, execution, dd, sonar, environmentId);
        persistDisplaySnapshot(execution, result, appendHistory);
        saveSnapshotTable(app.getId(), execution.getEnvironment().getId(), execution, branch, source, result);
    }

    private QualityGateResultDto loadSnapshotForEnvironment(UUID environmentId, PipelineExecution execution) {
        Optional<QualityGateSnapshot> fromTable = qualityGateSnapshotRepository
                .findFirstByEnvironmentIdOrderByCreatedAtDesc(environmentId);
        if (fromTable.isPresent()) {
            QualityGateResultDto dto = fromSnapshotEntity(fromTable.get());
            enrichWithPipelineRuntimeState(dto, execution);
            return dto;
        }
        QualityGateResultDto fromJson = loadStoredDisplaySnapshot(execution);
        if (fromJson != null) {
            enrichWithPipelineRuntimeState(fromJson, execution);
        }
        return fromJson;
    }

    /**
     * Enrichit un snapshot figé avec l'état courant du pipeline (en cours, timeline incomplète).
     */
    private void enrichWithPipelineRuntimeState(QualityGateResultDto dto, PipelineExecution execution) {
        if (dto == null || execution == null) {
            return;
        }
        PipelineStatus status = execution.getStatus();
        if (status != null) {
            dto.setPipelineStatus(status.name().toLowerCase(Locale.ROOT));
            dto.setPipelineFinished(status.isFinished());
        }
        boolean running = status != null && !status.isFinished();
        SecurityValidationJobState svState = securityValidationJobState(execution);
        if (svState == SecurityValidationJobState.FAILED && !running) {
            rebuildTimelineOnly(dto, execution);
            applySecurityValidationFailedState(dto, execution);
            return;
        }
        int jobCount = countJobsInStagesJson(execution);
        boolean frozenDisplay = hasFrozenQualityGateDisplay(dto, execution);
        boolean timelineThinBeforeRebuild = shouldRebuildTimelineFromJobs(dto, execution);

        if (running && !frozenDisplay) {
            dto.setStages(List.of());
            dto.setToolMetrics(List.of());
            applyPipelineInProgressState(dto, execution);
        } else {
            reconcileSnapshotDisplayMetrics(dto, execution);
            reconcileSecurityValidationStageFromGitlab(dto, execution);
            if (timelineThinBeforeRebuild) {
                mergeLiveStagesFromExecution(dto, execution);
            }
            if (running && frozenDisplay) {
                dto.setIncompleteRecommendationMessage(
                        "Pipeline encore actif sur GitLab — affichage basé sur le rapport security-validation.");
            }
            boolean timelineStillThin = shouldRebuildTimelineFromJobs(dto, execution);
            if (timelineStillThin && status != null && status.isFinished()) {
                String thinMsg = "Timeline incomplète (jobs GitLab non synchronisés). "
                        + "Cliquez « Actualiser » pour resynchroniser depuis GitLab.";
                if (dto.getIncompleteRecommendationMessage() == null || dto.getIncompleteRecommendationMessage().isBlank()) {
                    dto.setIncompleteRecommendationMessage(thinMsg);
                }
            }
            applyPipelineJobEvaluability(dto, execution);
        }
    }

    /**
     * Snapshot capturé trop tôt : payload ne contient que security-validation alors que stages_json
     * GitLab liste déjà plusieurs jobs — reconstruire la timeline à la lecture.
     */
    private boolean shouldRebuildTimelineFromJobs(QualityGateResultDto dto, PipelineExecution execution) {
        List<Map<String, Object>> jobs = getJobsFromStagesJson(execution);
        if (jobs.size() <= 1) {
            return false;
        }
        List<QualityGateStageDto> stages = dto.getStages();
        if (stages == null || stages.isEmpty()) {
            return true;
        }
        if (stages.size() == 1 && isSecurityValidationStage(stages.get(0).getName())) {
            return true;
        }
        return jobs.size() > stages.size() + 2;
    }

    /** Corrige security-validation figé en FAIL (verdict) alors que le job GitLab a réussi. */
    private void reconcileSecurityValidationStageFromGitlab(QualityGateResultDto dto, PipelineExecution execution) {
        if (dto == null || execution == null) {
            return;
        }
        SecurityValidationJobState sv = securityValidationJobState(execution);
        if (dto.getMetrics() == null) {
            dto.setMetrics(new LinkedHashMap<>());
        }
        dto.getMetrics().put("securityValidationGitlabFailed", sv == SecurityValidationJobState.FAILED);
        dto.getMetrics().put("securityValidationSucceeded", sv == SecurityValidationJobState.SUCCESS);
        if (sv != SecurityValidationJobState.SUCCESS) {
            return;
        }
        List<QualityGateStageDto> stages = dto.getStages();
        if (stages == null || stages.isEmpty()) {
            return;
        }
        Map<String, Object> storedGate = execution.getQualityGateJson();
        String ciRec = storedGate != null ? stringVal(storedGate.get("recommendation")) : null;
        String msg = ciRec != null
                ? "Job terminé avec succès — recommandation : " + ciRec
                : "Job security-validation terminé avec succès sur GitLab";
        List<QualityGateStageDto> patched = new ArrayList<>();
        boolean changed = false;
        for (QualityGateStageDto s : stages) {
            if (!isSecurityValidationStage(s.getName())) {
                patched.add(s);
                continue;
            }
            if ("FAIL".equals(s.getStatus()) || s.isBlocking()) {
                patched.add(s.toBuilder()
                        .status("PASS").statusLabel("Réussi")
                        .message(msg).blocking(false).build());
                changed = true;
            } else {
                patched.add(s);
            }
        }
        if (changed) {
            dto.setStages(patched);
        }
    }

    private boolean isSecurityValidationStage(String name) {
        if (name == null || name.isBlank()) {
            return false;
        }
        String n = name.toLowerCase(Locale.ROOT).replace('_', '-');
        return n.contains("security-validation");
    }

    private boolean hasFrozenQualityGateDisplay(QualityGateResultDto dto, PipelineExecution execution) {
        if (dto == null) {
            return false;
        }
        if (Boolean.TRUE.equals(dto.getMetricsFromSecurityValidation())) {
            return true;
        }
        if (dto.getMetrics() != null && Boolean.TRUE.equals(dto.getMetrics().get("metricsFromSecurityValidation"))) {
            return true;
        }
        if (Boolean.TRUE.equals(dto.getFromSnapshot()) && dto.getVerdict() != null
                && !"INDETERMINE".equalsIgnoreCase(dto.getVerdict())) {
            return true;
        }
        Map<String, Object> storedGate = execution != null ? execution.getQualityGateJson() : null;
        if (storedGate != null && storedGate.get("verdict") != null) {
            return true;
        }
        if (execution != null
                && securityValidationJobState(execution) == SecurityValidationJobState.SUCCESS) {
            return true;
        }
        boolean hasTools = dto.getToolMetrics() != null && !dto.getToolMetrics().isEmpty();
        boolean hasStages = dto.getStages() != null && !dto.getStages().isEmpty();
        boolean hasSq = dto.getSoftwareQuality() != null && !dto.getSoftwareQuality().isEmpty();
        return hasTools || hasStages || hasSq;
    }

    /**
     * Snapshot BDD : reconstitue outils / sévérités / Sonar depuis quality_gate_json (security-validation)
     * quand le payload figé est incomplet (capture CI précoce ou DefectDojo absent).
     */
    @SuppressWarnings("unchecked")
    private void reconcileSnapshotDisplayMetrics(QualityGateResultDto dto, PipelineExecution execution) {
        if (dto == null || execution == null) {
            return;
        }
        Map<String, Object> storedGate = execution.getQualityGateJson();
        Map<String, Object> summary = resolveEffectiveSummary(execution, storedGate);
        boolean hasTools = dto.getToolMetrics() != null && !dto.getToolMetrics().isEmpty();

        Map<String, Object> sonarFlat = Map.of();
        if (dto.getMetrics() != null && dto.getMetrics().get("sonarQube") instanceof Map<?, ?> sqMap) {
            sonarFlat = sonarFlatMetrics(new LinkedHashMap<>((Map<String, Object>) sqMap));
        }
        if (sonarFlat.isEmpty() && storedGate != null) {
            Map<String, Object> fromPipeline = buildSonarFromPipelineArtifacts(storedGate, summary);
            if (!fromPipeline.isEmpty()) {
                sonarFlat = sonarFlatMetrics(fromPipeline);
            }
        }
        if (!sonarFlat.isEmpty()) {
            enrichSonarFlatFromPipeline(sonarFlat, storedGate, summary);
        }

        if (!hasTools && !summary.isEmpty()) {
            List<QualityGateToolMetricDto> tools = buildToolMetrics(
                    summary, null, sonarFlat, true,
                    dto.getSoftwareQuality() != null ? dto.getSoftwareQuality() : List.of());
            List<Map<String, Object>> jobs = getJobsFromStagesJson(execution);
            List<QualityGateStageDto> stages = dto.getStages();
            if (stages == null || stages.isEmpty()) {
                stages = buildStages(jobs, summary, storedGate, sonarFlat, true);
            }
            attachStageToTools(tools, stages);
            dto.setToolMetrics(tools);
            if (stages != null && !stages.isEmpty()) {
                dto.setStages(stages);
            }
            dto.setMetricsFromSecurityValidation(true);
        }

        List<QualityGateToolMetricDto> toolsForAgg = dto.getToolMetrics();
        Map<String, Integer> bySev = buildBySeverity(null, summary, toolsForAgg, false);
        int sevSum = bySev.values().stream().mapToInt(Integer::intValue).sum();
        if (sevSum > 0) {
            if (dto.getMetrics() == null) {
                dto.setMetrics(new LinkedHashMap<>());
            }
            dto.getMetrics().put("bySeverity", bySev);
            dto.getMetrics().put("totalVulnerabilities", sevSum);
        }

        if (!sonarFlat.isEmpty() && (dto.getSonarAvailability() == null || !dto.getSonarAvailability().isAvailable())) {
            dto.setSonarAvailability(SonarAvailabilityDto.builder()
                    .available(true)
                    .message("Métriques SonarQube (rapport security-validation)")
                    .build());
            if (dto.getMetrics() == null) {
                dto.setMetrics(new LinkedHashMap<>());
            }
            dto.getMetrics().put("sonarQube", buildSonarMetricsMap(sonarFlat));
            dto.setSoftwareQuality(finalizeSoftwareQualityDimensions(
                    buildSoftwareQualityDimensions(sonarFlat, true),
                    sonarFlat, summary, storedGate));
        } else if (!sonarFlat.isEmpty()
                && (dto.getSoftwareQuality() == null || dto.getSoftwareQuality().isEmpty()
                || dto.getSoftwareQuality().stream().allMatch(d -> d.getIssues() == 0))) {
            List<SoftwareQualityDimensionDto> rebuilt = finalizeSoftwareQualityDimensions(
                    buildSoftwareQualityDimensions(sonarFlat, true),
                    sonarFlat, summary, storedGate);
            dto.setSoftwareQuality(rebuilt);
            syncSoftwareQualityToSonarFlat(sonarFlat, rebuilt);
            if (dto.getMetrics() != null) {
                dto.getMetrics().put("sonarQube", buildSonarMetricsMap(sonarFlat));
            }
        }

        if (Boolean.FALSE.equals(dto.getDefectDojoAvailable()) || dto.getMetricsFromSecurityValidation() == null) {
            if (!summary.isEmpty()) {
                dto.setMetricsFromSecurityValidation(true);
                dto.setDefectDojoAvailable(false);
            }
        }

        List<Map<String, Object>> jobs = getJobsFromStagesJson(execution);
        if ((dto.getStages() == null || dto.getStages().isEmpty()) && !jobs.isEmpty()) {
            List<QualityGateStageDto> rebuilt = buildStages(jobs, summary, storedGate, sonarFlat, !summary.isEmpty());
            if (!rebuilt.isEmpty()) {
                dto.setStages(rebuilt);
                if (dto.getToolMetrics() != null && !dto.getToolMetrics().isEmpty()) {
                    attachStageToTools(dto.getToolMetrics(), rebuilt);
                }
            }
        }

        if ((dto.getPracticalAdvice() == null || dto.getPracticalAdvice().isEmpty())
                && dto.getVerdict() != null && !summary.isEmpty()) {
            List<QualityGateToolMetricDto> tools = dto.getToolMetrics() != null
                    ? dto.getToolMetrics() : List.of();
            List<QualityGateStageDto> stages = dto.getStages() != null ? dto.getStages() : List.of();
            List<String> advice = buildPracticalAdvice(dto.getVerdict(), stages, summary, tools, sonarFlat);
            if (!advice.isEmpty()) {
                dto.setPracticalAdvice(advice);
                dto.setDetailedRecommendations(advice);
            }
        }

        refreshSonarToolMetric(dto, sonarFlat);
    }

    private Map<String, Object> buildSonarMetricsMap(Map<String, Object> sonarFlat) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("bugs", intVal(sonarFlat.get("bugs")));
        m.put("vulnerabilities", intVal(sonarFlat.get("vulnerabilities")));
        m.put("codeSmells", intVal(sonarFlat.get("code_smells")));
        m.put("hotspots", intVal(sonarFlat.get("security_hotspots")));
        m.put("coverage", sonarFlat.get("coverage"));
        m.put("ncloc", intVal(sonarFlat.get("ncloc")));
        m.put("openSecurity", intVal(sonarFlat.get("software_quality_security_issues")));
        m.put("openReliability", intVal(sonarFlat.get("software_quality_reliability_issues")));
        m.put("openMaintainability", intVal(sonarFlat.get("software_quality_maintainability_issues")));
        Object qg = sonarFlat.get("quality_gate_status");
        if (qg != null) {
            m.put("status", String.valueOf(qg));
        }
        m.put("bySeverity", sonarViolationBySeverity(sonarFlat));
        return m;
    }

    private static final String PIPELINE_PENDING_GATE_MSG =
            "Pipeline en cours — condition non encore vérifiée";

    private static final String SONAR_JOB_FAILED_MSG =
            "Le stage SonarQube ne s'est pas terminé avec succès — métriques Sonar non affichées, "
                    + "recommandation incomplète.";

    private static final String DEFECTDOJO_FALLBACK_MSG =
            "DefectDojo indisponible — métriques affichées depuis le rapport security-validation.";

    private static final String SECURITY_VALIDATION_FAILED_MSG =
            "Le stage security-validation a échoué — le pipeline ne s'est pas terminé avec succès.";

    private void applySecurityValidationFailedState(QualityGateResultDto dto, PipelineExecution execution) {
        String pipelineId = dto.getPipelineId();
        if ((pipelineId == null || pipelineId.isBlank())
                && execution != null && execution.getGitlabPipelineId() != null) {
            pipelineId = String.valueOf(execution.getGitlabPipelineId());
            dto.setPipelineId(pipelineId);
        }
        dto.setVerdict("INDETERMINE");
        dto.setVerdictSource("SECURITY_VALIDATION_FAILED");
        dto.setSummary("Pipeline"
                + (pipelineId != null && !pipelineId.isBlank() ? " #" + pipelineId : "")
                + " — security-validation en échec. Recommandation de déploiement indisponible.");
        dto.setSecurityScore(null);
        dto.setToolMetrics(List.of());
        dto.setSoftwareQuality(List.of());
        dto.setSoftwareQualitySeverity(Map.of());
        dto.setHardGateViolations(List.of());
        dto.setHardGateIndeterminate(pipelinePendingHardGates());
        dto.setIndeterminateSources(List.of("Centralisation des vulnérabilités", "Security-Validation"));
        dto.setIncompleteRecommendationMessage(
                buildIncompleteRecommendationMessage(List.of("Centralisation des vulnérabilités")));
        dto.setDefectDojoAvailable(false);
        dto.setMetricsFromSecurityValidation(false);
        dto.setCanCaptureSnapshot(false);
        dto.setSonarAvailability(SonarAvailabilityDto.builder()
                .available(false)
                .message(SECURITY_VALIDATION_FAILED_MSG)
                .build());

        List<String> advice = List.of(
                "1. Le pipeline ne s'est pas terminé avec succès : ouvrez GitLab, identifiez le job en échec "
                        + "(security-validation ou un scan en amont) et corrigez les erreurs avant de relancer.",
                "2. Une fois tous les stages au vert, relancez security-validation pour obtenir une recommandation complète."
        );
        dto.setPracticalAdvice(advice);
        dto.setDetailedRecommendations(advice);
        dto.setVerdictExplanation(List.of(
                "Le stage security-validation n'a pas réussi — outils et conditions de déploiement non évalués.",
                "Consultez la timeline GitLab ci-dessous, corrigez les jobs en échec puis relancez le pipeline."
        ));

        Map<String, Object> metrics = dto.getMetrics() != null
                ? new LinkedHashMap<>(dto.getMetrics())
                : new LinkedHashMap<>();
        metrics.put("securityValidationFailed", true);
        metrics.put("securityValidationGitlabFailed", true);
        metrics.put("totalVulnerabilities", 0);
        metrics.put("bySeverity", Map.of(
                "critical", 0, "high", 0, "medium", 0, "low", 0, "info", 0));
        metrics.put("failedStages", 0);
        metrics.put("blockingStages", 0);
        metrics.put("warningStages", 0);
        metrics.put("secrets", 0);
        metrics.put("defectDojoAvailable", false);
        metrics.put("metricsFromSecurityValidation", false);
        metrics.put("pipelineFinished", execution != null && execution.getStatus() != null
                && execution.getStatus().isFinished());
        dto.setMetrics(metrics);
    }

    /** Timeline GitLab uniquement (sans outils / SQ). */
    private void rebuildTimelineOnly(QualityGateResultDto dto, PipelineExecution execution) {
        List<Map<String, Object>> jobs = getJobsFromStagesJson(execution);
        if (jobs.isEmpty()) {
            return;
        }
        Map<String, Object> storedGate = execution.getQualityGateJson();
        Map<String, Object> summary = resolveEffectiveSummary(execution, storedGate);
        Map<String, Object> sonarFlat = resolveSonarFlatForPresentation(dto, storedGate, summary);
        List<QualityGateStageDto> stages = buildStages(
                jobs, summary, storedGate, sonarFlat, !summary.isEmpty());
        if (!stages.isEmpty()) {
            dto.setStages(stages);
        }
    }

    private void applyPipelineInProgressState(QualityGateResultDto dto, PipelineExecution execution) {
        dto.setVerdict("INDETERMINE");
        dto.setVerdictSource("PIPELINE_IN_PROGRESS");
        dto.setSummary("Pipeline"
                + (execution.getGitlabPipelineId() != null ? " #" + execution.getGitlabPipelineId() : "")
                + " en cours — le quality gate complet sera disponible après la fin des scans.");
        dto.setIncompleteRecommendationMessage(
                "Pipeline en cours — données partielles, ne pas déployer sur cette base.");
        dto.setSecurityScore(null);
        dto.setHardGateViolations(List.of());
        dto.setHardGateIndeterminate(pipelinePendingHardGates());
        dto.setIndeterminateSources(List.of("Pipeline"));
        dto.setDefectDojoAvailable(false);
        dto.setSonarAvailability(SonarAvailabilityDto.builder()
                .available(false)
                .message(PIPELINE_PENDING_GATE_MSG)
                .build());
    }

    /** Reconstruit timeline + cartes outils depuis stages_json GitLab et quality_gate_json (sans persister). */
    @SuppressWarnings("unchecked")
    private void mergeLiveStagesFromExecution(QualityGateResultDto dto, PipelineExecution execution) {
        List<Map<String, Object>> jobs = getJobsFromStagesJson(execution);
        if (jobs.isEmpty()) {
            return;
        }
        Map<String, Object> storedGate = execution.getQualityGateJson();
        Map<String, Object> summary = resolveEffectiveSummary(execution, storedGate);
        boolean hasSummary = !summary.isEmpty();
        Map<String, Object> sonarFlat = resolveSonarFlatForPresentation(dto, storedGate, summary);
        List<QualityGateStageDto> stages = buildStages(jobs, summary, storedGate, sonarFlat, hasSummary);
        dto.setStages(stages);

        List<SoftwareQualityDimensionDto> softwareQuality = dto.getSoftwareQuality() != null
                ? dto.getSoftwareQuality()
                : buildSoftwareQualityDimensions(sonarFlat, !sonarFlat.isEmpty());
        List<QualityGateToolMetricDto> tools = buildToolMetrics(
                summary, null, sonarFlat, hasSummary, softwareQuality);
        attachStageToTools(tools, stages);
        dto.setToolMetrics(tools);
        dto.setCanCaptureSnapshot(canPersistSnapshot(execution));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> resolveSonarFlatForPresentation(
            QualityGateResultDto dto,
            Map<String, Object> storedGate,
            Map<String, Object> summary
    ) {
        if (dto.getMetrics() != null && dto.getMetrics().get("sonarQube") instanceof Map<?, ?> sq) {
            Map<String, Object> fromDto = sonarFlatMetrics(new LinkedHashMap<>((Map<String, Object>) sq));
            if (!fromDto.isEmpty()) {
                return fromDto;
            }
        }
        Map<String, Object> fromPipeline = buildSonarFromPipelineArtifacts(storedGate, summary);
        if (!fromPipeline.isEmpty()) {
            return sonarFlatMetrics(fromPipeline);
        }
        return Map.of();
    }

    private List<HardGateViolationDto> pipelinePendingHardGates() {
        return List.of(
                HardGateViolationDto.builder().id("secrets").label("Secrets exposés (Gitleaks)")
                        .message(PIPELINE_PENDING_GATE_MSG).status("INDETERMINATE").build(),
                HardGateViolationDto.builder().id("dd_critical").label("Vulnérabilités critiques (DefectDojo)")
                        .message(PIPELINE_PENDING_GATE_MSG).status("INDETERMINATE").build(),
                HardGateViolationDto.builder().id("sonar_blocker").label("Issues Blocker (SonarQube)")
                        .message(PIPELINE_PENDING_GATE_MSG).status("INDETERMINATE").build(),
                HardGateViolationDto.builder().id("sonar_qg").label("Quality Gate SonarQube")
                        .message(PIPELINE_PENDING_GATE_MSG).status("INDETERMINATE").build()
        );
    }

    private QualityGateResultDto loadSnapshotForBranch(UUID applicationId, String branch) {
        return qualityGateSnapshotRepository
                .findFirstByApplicationIdAndBranchOrderByCreatedAtDesc(applicationId, branch)
                .map(this::fromSnapshotEntity)
                .orElse(null);
    }

    /** Lecture BDD uniquement — branche, puis dernier snapshot app, puis quality_gate_json. */
    private QualityGateResultDto tryLoadSnapshotFromDb(
            UUID applicationId,
            String branch,
            PipelineExecution execution
    ) {
        if (branch != null && !branch.isBlank()) {
            QualityGateResultDto byBranch = loadSnapshotForBranch(applicationId, branch);
            if (byBranch != null) {
                return byBranch;
            }
        }
        Optional<QualityGateSnapshot> latestApp = qualityGateSnapshotRepository
                .findFirstByApplicationIdOrderByCreatedAtDesc(applicationId);
        if (latestApp.isPresent()) {
            QualityGateResultDto dto = fromSnapshotEntity(latestApp.get());
            if (dto != null) {
                return dto;
            }
        }
        if (execution != null) {
            QualityGateResultDto fromExec = loadStoredDisplaySnapshot(execution);
            if (fromExec != null) {
                fromExec.setFromSnapshot(true);
                fromExec.setSnapshotRecordSource("PIPELINE_JSON");
                return fromExec;
            }
        }
        return null;
    }

    private QualityGateResultDto fromSnapshotEntity(QualityGateSnapshot row) {
        QualityGateResultDto dto = deserializeSnapshotPayload(row.getPayload());
        if (dto == null) {
            return null;
        }
        dto.setSnapshotId(row.getId());
        dto.setSnapshotRecordSource(row.getSource());
        dto.setFromSnapshot(true);
        if (dto.getPipelineId() == null && row.getGitlabPipelineId() != null) {
            dto.setPipelineId(String.valueOf(row.getGitlabPipelineId()));
        }
        if (dto.getEnvironmentId() == null) {
            dto.setEnvironmentId(row.getEnvironmentId());
        }
        if (row.getEvaluatedAt() != null) {
            dto.setEvaluatedAt(row.getEvaluatedAt());
        }
        if (dto.getBranch() == null || dto.getBranch().isBlank()) {
            dto.setBranch(row.getBranch());
        }
        if ((dto.getNcloc() == null || dto.getNcloc() <= 0) && row.getNcloc() != null && row.getNcloc() > 0) {
            dto.setNcloc(row.getNcloc());
            if (dto.getNclocSource() == null) {
                dto.setNclocSource("SNAPSHOT");
            }
            enrichMetricsNcloc(dto, row.getNcloc());
        }
        return dto;
    }

    private void enrichMetricsNcloc(QualityGateResultDto dto, int ncloc) {
        if (dto.getMetrics() == null) {
            dto.setMetrics(new LinkedHashMap<>());
        }
        dto.getMetrics().put("ncloc", ncloc);
        Object sonarObj = dto.getMetrics().get("sonarQube");
        if (sonarObj instanceof Map<?, ?> sonarMap) {
            @SuppressWarnings("unchecked")
            Map<String, Object> sonar = (Map<String, Object>) sonarMap;
            sonar.put("ncloc", ncloc);
        } else if (ncloc > 0) {
            Map<String, Object> sonar = new LinkedHashMap<>();
            sonar.put("ncloc", ncloc);
            dto.getMetrics().put("sonarQube", sonar);
        }
    }

    private record NclocResolution(int value, String source) {}

    private QualityGateSnapshotHistoryItemDto toHistoryItem(QualityGateSnapshot row) {
        String envName = environmentRepository.findById(row.getEnvironmentId())
                .map(EphemeralEnvironment::getEnvironmentName)
                .orElse(null);
        return QualityGateSnapshotHistoryItemDto.builder()
                .snapshotId(row.getId())
                .environmentId(row.getEnvironmentId())
                .environmentName(envName)
                .branch(row.getBranch())
                .gitlabPipelineId(row.getGitlabPipelineId())
                .pipelineId(row.getGitlabPipelineId() != null ? String.valueOf(row.getGitlabPipelineId()) : null)
                .evaluatedAt(row.getEvaluatedAt())
                .createdAt(row.getCreatedAt())
                .source(row.getSource())
                .verdict(extractVerdictFromPayload(row.getPayload()))
                .build();
    }

    @SuppressWarnings("unchecked")
    private String extractVerdictFromPayload(Map<String, Object> payload) {
        if (payload == null) {
            return null;
        }
        Object verdict = payload.get("verdict");
        return verdict != null ? String.valueOf(verdict) : null;
    }

    @SuppressWarnings("unchecked")
    private QualityGateResultDto deserializeSnapshotPayload(Map<String, Object> payload) {
        if (payload == null || payload.isEmpty()) return null;
        try {
            return objectMapper.convertValue(payload, QualityGateResultDto.class);
        } catch (Exception e) {
            log.warn("Payload snapshot quality gate illisible: {}", e.getMessage());
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private void saveSnapshotTable(
            UUID applicationId,
            UUID environmentId,
            PipelineExecution execution,
            String branch,
            String source,
            QualityGateResultDto dto
    ) {
        QualityGateSnapshot row = qualityGateSnapshotRepository
                .findByPipelineExecutionId(execution.getId())
                .orElseGet(QualityGateSnapshot::new);
        row.setApplicationId(applicationId);
        row.setEnvironmentId(environmentId);
        row.setPipelineExecutionId(execution.getId());
        row.setBranch(branch != null ? branch : "");
        row.setGitlabPipelineId(execution.getGitlabPipelineId());
        row.setSource(source != null ? source : SNAPSHOT_SOURCE_MANUAL);
        row.setEvaluatedAt(dto.getEvaluatedAt() != null ? dto.getEvaluatedAt() : Instant.now());
        row.setNcloc(dto.getNcloc());
        row.setPayload(objectMapper.convertValue(dto, Map.class));
        qualityGateSnapshotRepository.saveAndFlush(row);
        log.info("Snapshot QG persisté table id={} pipelineExec={} env={} gitlabPipeline={}",
                row.getId(), execution.getId(), environmentId, execution.getGitlabPipelineId());
    }

    @SuppressWarnings("unchecked")
    private QualityGateResultDto loadStoredDisplaySnapshot(PipelineExecution execution) {
        if (execution == null || execution.getQualityGateJson() == null) return null;
        Object snap = execution.getQualityGateJson().get("displaySnapshot");
        if (snap == null) return null;
        try {
            return objectMapper.convertValue(snap, QualityGateResultDto.class);
        } catch (Exception e) {
            log.warn("Snapshot quality gate illisible: {}", e.getMessage());
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private void persistDisplaySnapshot(PipelineExecution execution, QualityGateResultDto dto, boolean appendHistory) {
        Map<String, Object> gate = execution.getQualityGateJson();
        if (gate == null) {
            gate = new LinkedHashMap<>();
        }
        if (appendHistory && gate.get("displaySnapshot") != null) {
            appendSnapshotHistoryEntry(gate, gate);
        }
        gate.put("displaySnapshot", objectMapper.convertValue(dto, Map.class));
        gate.put("snapshotSavedAt", Instant.now().toString());
        execution.setQualityGateJson(gate);
        pipelineExecutionRepository.save(execution);
    }

    @SuppressWarnings("unchecked")
    private void appendSnapshotHistoryEntry(Map<String, Object> gate, Map<String, Object> previousGate) {
        List<Map<String, Object>> history = gate.get("snapshotHistory") instanceof List<?> list
                ? new ArrayList<>((List<Map<String, Object>>) list)
                : new ArrayList<>();
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("evaluatedAt", previousGate.get("evaluatedAt"));
        entry.put("pipelineId", previousGate.get("pipelineId"));
        entry.put("snapshotSavedAt", previousGate.get("snapshotSavedAt"));
        entry.put("snapshot", previousGate.get("displaySnapshot"));
        history.add(0, entry);
        if (history.size() > SNAPSHOT_HISTORY_MAX) {
            history = new ArrayList<>(history.subList(0, SNAPSHOT_HISTORY_MAX));
        }
        gate.put("snapshotHistory", history);
    }

    private Instant parseInstant(Object value) {
        if (value == null) return null;
        try {
            return Instant.parse(String.valueOf(value));
        } catch (Exception e) {
            return null;
        }
    }

    private Map<String, Object> fetchSonarForQualityGate(AppService app, String branch) {
        return fetchSonarForQualityGate(app, branch, null);
    }

    /**
     * Sonar : métriques CI uniquement si le job sonarqube-scan a réussi ; sinon pas de fallback live.
     */
    private Map<String, Object> fetchSonarForQualityGate(AppService app, String branch, PipelineExecution execution) {
        if (execution != null) {
            SonarScanJobState sonarJob = sonarScanJobState(execution);
            if (sonarJob == SonarScanJobState.FAILED) {
                Map<String, Object> unavailable = new LinkedHashMap<>();
                unavailable.put("sonar_available", false);
                unavailable.put("sonar_job_failed", true);
                unavailable.put("branch_fallback_message", SONAR_JOB_FAILED_MSG);
                return unavailable;
            }
            if (sonarJob == SonarScanJobState.PENDING) {
                Map<String, Object> unavailable = new LinkedHashMap<>();
                unavailable.put("sonar_available", false);
                unavailable.put("branch_fallback_message", "Stage SonarQube non terminé — scan en cours ou absent.");
                return unavailable;
            }
            Map<String, Object> storedGate = execution.getQualityGateJson();
            Map<String, Object> summary = resolveEffectiveSummary(execution, storedGate);
            Map<String, Object> fromPipeline = buildSonarFromPipelineArtifacts(storedGate, summary);
            if (!fromPipeline.isEmpty()) {
                fromPipeline.put("sonar_available", true);
                return fromPipeline;
            }
        }
        String projectKey = SonarProjectKeyUtil.deriveSonarProjectKey(app.getGitRepositoryUrl());
        if (projectKey.isBlank()) {
            log.warn("Impossible de dériver projectKey Sonar depuis {}", app.getGitRepositoryUrl());
            Map<String, Object> unavailable = new LinkedHashMap<>();
            unavailable.put("sonar_available", false);
            return unavailable;
        }
        try {
            return gitLabService.fetchSonarForQualityGate(projectKey, branch);
        } catch (Exception e) {
            log.debug("SonarQube indisponible: {}", e.getMessage());
            Map<String, Object> unavailable = new LinkedHashMap<>();
            unavailable.put("sonar_available", false);
            unavailable.put("sonar_project_key", projectKey);
            return unavailable;
        }
    }

    /**
     * Récupère le dashboard DefectDojo pour un snapshot.
     * La capture tourne en contexte asynchrone (webhook, AFTER_COMMIT, runAsync) sans
     * SecurityContext. getDashboard2() appelle currentUser() → sans utilisateur il lève
     * "non authentifié", l'exception est avalée, dd reste null. On impersonne donc le
     * propriétaire de l'application le temps de l'appel.
     */
    private DefectDojoDashboard2Response fetchDefectDojoForSnapshot(
            AppService app,
            PipelineExecution execution,
            String branch,
            UUID environmentId
    ) {
        return runWithSnapshotAuth(app, execution, () -> {
            try {
                return defectDojoService.getDashboard2(app.getId(), branch, environmentId);
            } catch (Exception e) {
                log.warn("DefectDojo indisponible pour snapshot (env {}): {}", environmentId, e.getMessage());
                return null;
            }
        });
    }

    private <T> T runWithSnapshotAuth(AppService app, PipelineExecution execution, Supplier<T> action) {
        Authentication existing = SecurityContextHolder.getContext().getAuthentication();
        boolean alreadyAuthenticated = existing != null
                && existing.getName() != null && !existing.getName().isBlank();
        if (alreadyAuthenticated) {
            return action.get();
        }
        String username = resolveSnapshotUsername(app, execution);
        if (username == null) {
            log.warn("Snapshot QG : utilisateur propriétaire introuvable — DefectDojo ignoré");
            return action.get();
        }
        try {
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(username, null, List.of()));
            return action.get();
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    /**
     * Utilisateur à impersonner pour DefectDojo (filtre findByIdAndCreatedBy) :
     * créateur de l'application, sinon demandeur de l'environnement en repli.
     */
    private String resolveSnapshotUsername(AppService app, PipelineExecution execution) {
        try {
            if (app != null && app.getCreatedBy() != null
                    && app.getCreatedBy().getUsername() != null) {
                return app.getCreatedBy().getUsername();
            }
        } catch (Exception ignored) {
        }
        try {
            if (execution.getEnvironment() != null
                    && execution.getEnvironment().getRequestedBy() != null
                    && execution.getEnvironment().getRequestedBy().getUsername() != null) {
                return execution.getEnvironment().getRequestedBy().getUsername();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    @Transactional(readOnly = true)
    public String generateAiInsight(UUID applicationId, String branch, UUID environmentId) {
        QualityGateResultDto result = getForApplication(applicationId, branch, environmentId, false, null);
        try {
            String json = objectMapper.writeValueAsString(buildAiInsightContext(result));
            return aiAnalysisService.generateQualityGateInsight(json);
        } catch (Exception e) {
            log.warn("Sérialisation quality gate pour IA: {}", e.getMessage());
            return null;
        }
    }

    @Transactional(readOnly = true)
    public String generateAiInsight(UUID applicationId, String branch) {
        return generateAiInsight(applicationId, branch, null);
    }

    /** Contexte IA ciblé (score, SQ, stages bloquants) — évite un JSON brut trop volumineux. */
    private Map<String, Object> buildAiInsightContext(QualityGateResultDto result) {
        Map<String, Object> ctx = new LinkedHashMap<>();
        ctx.put("branch", result.getBranch());
        ctx.put("verdict", result.getVerdict());
        ctx.put("ciVerdict", result.getCiVerdict());
        ctx.put("verdictSource", result.getVerdictSource());
        ctx.put("pipelineStatus", result.getPipelineStatus());
        ctx.put("summary", result.getSummary());
        ctx.put("incompleteRecommendationMessage", result.getIncompleteRecommendationMessage());
        ctx.put("hardGateViolations", result.getHardGateViolations());
        ctx.put("hardGateIndeterminate", result.getHardGateIndeterminate());
        ctx.put("securityScore", result.getSecurityScore());
        Map<String, Object> metricsCtx = new LinkedHashMap<>();
        if (result.getMetrics() != null) {
            metricsCtx.put("bySeverity", result.getMetrics().get("bySeverity") != null
                    ? result.getMetrics().get("bySeverity") : Map.of());
            metricsCtx.put("totalVulnerabilities", result.getMetrics().get("totalVulnerabilities"));
            metricsCtx.put("secrets", result.getMetrics().get("secrets"));
        }
        ctx.put("metrics", metricsCtx);
        boolean pipelineActive = isPipelineActiveForAi(result);
        if (!pipelineActive) {
            ctx.put("softwareQuality", result.getSoftwareQuality());
            ctx.put("softwareQualitySeverity", result.getSoftwareQualitySeverity());
            ctx.put("sonarAvailability", result.getSonarAvailability());
            ctx.put("sonarQube", result.getMetrics() != null ? result.getMetrics().get("sonarQube") : null);
        }
        ctx.put("toolMetrics", result.getToolMetrics());
        ctx.put("thresholds", result.getThresholds());
        ctx.put("blockingStages", result.getStages() != null
                ? result.getStages().stream()
                .filter(s -> s.isBlocking() && "FAIL".equals(s.getStatus()))
                .map(s -> Map.of(
                        "name", s.getName(),
                        "toolLabel", s.getToolLabel() != null ? s.getToolLabel() : s.getName(),
                        "message", s.getMessage() != null ? s.getMessage() : ""
                ))
                .toList()
                : List.of());
        ctx.put("warningStages", result.getStages() != null
                ? result.getStages().stream()
                .filter(s -> "WARN".equals(s.getStatus()))
                .map(s -> s.getToolLabel() != null ? s.getToolLabel() : s.getName())
                .toList()
                : List.of());
        ctx.put("verdictExplanation", result.getVerdictExplanation());
        return ctx;
    }

    private boolean isPipelineActiveForAi(QualityGateResultDto result) {
        if (result == null) {
            return false;
        }
        if ("PIPELINE_IN_PROGRESS".equals(result.getVerdictSource())) {
            return true;
        }
        String ps = result.getPipelineStatus();
        if (ps == null) {
            return false;
        }
        String lower = ps.toLowerCase(Locale.ROOT);
        return "running".equals(lower) || "pending".equals(lower) || "created".equals(lower);
    }

    @Transactional(readOnly = true)
    public List<String> listBranches(UUID applicationId) {
        User user = currentUser();
        AppService app = applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));

        LinkedHashSet<String> merged = new LinkedHashSet<>();
        String projectKey = SonarProjectKeyUtil.deriveSonarProjectKey(app.getGitRepositoryUrl());
        if (!projectKey.isBlank()) {
            try {
                merged.addAll(gitLabService.listSonarProjectBranches(projectKey));
            } catch (Exception e) {
                log.debug("Branches Sonar indisponibles: {}", e.getMessage());
            }
        }
        try {
            DefectDojoDashboard2Response dd = defectDojoService.getDashboard2(applicationId, null);
            if (dd.getBranches() != null) {
                merged.addAll(dd.getBranches());
            }
        } catch (Exception ignored) {
        }
        environmentRepository.findByService_Id(applicationId).stream()
                .map(EphemeralEnvironment::getGitBranch)
                .filter(Objects::nonNull)
                .forEach(merged::add);
        if (merged.isEmpty()) {
            merged.add("main");
            merged.add("master");
            merged.add("test");
        }
        return merged.stream().sorted().toList();
    }

    private List<String> mergeAvailableBranches(
            String requestedBranch,
            Map<String, Object> sonar,
            DefectDojoDashboard2Response dd
    ) {
        LinkedHashSet<String> merged = new LinkedHashSet<>();
        Object resolutionObj = sonar.get("branch_resolution");
        if (resolutionObj instanceof SonarBranchResolution resolution
                && resolution.getAvailableBranches() != null) {
            merged.addAll(resolution.getAvailableBranches());
        }
        if (requestedBranch != null && !requestedBranch.isBlank()) {
            merged.add(requestedBranch.trim());
        }
        if (dd != null && dd.getBranches() != null) {
            merged.addAll(dd.getBranches());
        }
        if (merged.isEmpty()) {
            merged.add("main");
            merged.add("master");
            merged.add("test");
        }
        return merged.stream().sorted().toList();
    }

    private QualityGateResultDto buildResult(
            AppService app,
            String branch,
            PipelineExecution execution,
            DefectDojoDashboard2Response dd,
            Map<String, Object> sonar,
            UUID environmentId
    ) {
        if (execution != null && securityValidationJobState(execution) == SecurityValidationJobState.FAILED) {
            QualityGateResultDto failed = QualityGateResultDto.builder()
                    .applicationId(app.getId())
                    .branch(branch)
                    .environmentId(environmentId != null ? environmentId
                            : (execution.getEnvironment() != null ? execution.getEnvironment().getId() : null))
                    .pipelineId(execution.getGitlabPipelineId() != null
                            ? String.valueOf(execution.getGitlabPipelineId()) : null)
                    .pipelineStatus(execution.getStatus() != null
                            ? execution.getStatus().name().toLowerCase(Locale.ROOT) : null)
                    .pipelineFinished(execution.getStatus() != null && execution.getStatus().isFinished())
                    .stages(List.of())
                    .toolMetrics(List.of())
                    .metrics(new LinkedHashMap<>())
                    .thresholds(QualityGateThresholds.asMap())
                    .availableBranches(mergeAvailableBranches(branch, Map.of(), dd))
                    .build();
            if (execution.getStagesJson() != null) {
                failed.setPipelineWebUrl(stringVal(execution.getStagesJson().get("webUrl")));
            }
            rebuildTimelineOnly(failed, execution);
            applySecurityValidationFailedState(failed, execution);
            return failed;
        }
        Map<String, Object> storedGate = execution != null ? execution.getQualityGateJson() : null;
        Map<String, Object> summary = resolveEffectiveSummary(execution, storedGate);
        boolean pipelineFinished = execution != null && execution.getStatus() != null && execution.getStatus().isFinished();
        SonarScanJobState sonarJobState = sonarScanJobState(execution);
        boolean sonarJobFailed = sonarJobState == SonarScanJobState.FAILED;
        if (sonarJobFailed) {
            sonar = Map.of(
                    "sonar_available", false,
                    "sonar_job_failed", true,
                    "branch_fallback_message", SONAR_JOB_FAILED_MSG);
        } else {
            sonar = mergePipelineSonarIfNeeded(sonar, storedGate, summary, sonarJobState);
        }
        boolean hasSummary = !summary.isEmpty();
        boolean securityValidationDone = securityValidationJobState(execution) == SecurityValidationJobState.SUCCESS
                || (storedGate != null && storedGate.get("verdict") != null);
        UUID scopedEnvId = environmentId != null
                ? environmentId
                : (execution != null && execution.getEnvironment() != null
                        ? execution.getEnvironment().getId() : null);
        boolean usePipelineSummary = hasSummary;
        Map<String, Integer> ddByTool = dd != null ? dd.getByTool() : null;
        boolean defectDojoUiAvailable = isDefectDojoAvailableForQualityGate(dd, execution);
        boolean preferDefectDojoTools = defectDojoUiAvailable
                && ddByTool != null
                && ddByTool.values().stream().anyMatch(v -> v != null && v > 0);
        boolean hasSummaryForTools = !preferDefectDojoTools && (usePipelineSummary || !defectDojoUiAvailable);
        boolean metricsFromSecurityValidation = !defectDojoUiAvailable && (hasSummary || securityValidationDone);
        DdCriticalResolution ddCriticalRes = resolveDdCritical(dd, summary, storedGate, execution);
        int ddCritical = ddCriticalRes.critical();

        List<Map<String, Object>> jobs = execution != null
                ? getJobsFromStagesJson(execution)
                : List.of();
        Map<String, Object> sonarFlat = sonarJobFailed ? Map.of() : sonarFlatMetrics(sonar);
        if (!sonarFlat.isEmpty()) {
            enrichSonarFlatFromPipeline(sonarFlat, storedGate, summary);
        }
        NclocResolution nclocResolution = resolveNcloc(sonarFlat, summary, storedGate);
        int resolvedNcloc = nclocResolution.value();
        boolean sonarDisplayAvailable = !sonarJobFailed && (isSonarLiveAvailable(sonar) || !sonarFlat.isEmpty());
        SonarAvailabilityDto sonarAvailability = buildSonarAvailability(sonar, app, sonarDisplayAvailable);
        List<SoftwareQualityDimensionDto> softwareQuality = buildSoftwareQualityDimensions(
                sonarFlat, sonarDisplayAvailable);
        softwareQuality = finalizeSoftwareQualityDimensions(softwareQuality, sonarFlat, summary, storedGate);
        syncSoftwareQualityToSonarFlat(sonarFlat, softwareQuality);
        Map<String, Integer> softwareQualitySeverity = buildSoftwareQualitySeverity(sonarFlat);

        boolean showPipelineDetail = pipelineFinished || securityValidationDone || hasSummary;
        List<QualityGateToolMetricDto> toolMetrics = showPipelineDetail
                ? buildToolMetrics(summary, ddByTool, sonarFlat, hasSummaryForTools, softwareQuality)
                : List.of();
        Map<String, Integer> bySeverity = buildBySeverity(dd, summary, toolMetrics, defectDojoUiAvailable);

        Map<String, Object> effectiveSummary = usePipelineSummary || metricsFromSecurityValidation
                ? summary
                : syntheticSummaryFromTools(toolMetrics);
        List<QualityGateStageDto> stages = showPipelineDetail
                ? buildStages(jobs, effectiveSummary, storedGate, sonarFlat,
                        usePipelineSummary || metricsFromSecurityValidation)
                : List.of();
        if (showPipelineDetail) {
            attachStageToTools(toolMetrics, stages);
            if (sonarJobFailed) {
                clearSonarToolMetrics(toolMetrics, stages);
            } else {
                refreshSonarToolMetric(toolMetrics, sonarFlat, softwareQuality, null);
            }
        }
        boolean secretsEvaluable = isSecretsJobEvaluable(execution);
        int secretsForMetrics = secretsEvaluable ? intVal(effectiveSummary.get("secrets")) : 0;
        int sonarBlockers = sonarViolationCount(sonarFlat, "blocker");
        int sonarCritical = sonarViolationCount(sonarFlat, "critical");
        Map<String, Object> metrics = buildMetrics(
                bySeverity, effectiveSummary, stages, sonarFlat, dd, softwareQuality, softwareQualitySeverity,
                resolvedNcloc);
        metrics.put("secrets", secretsForMetrics);
        metrics.put("defectDojoAvailable", defectDojoUiAvailable);
        metrics.put("metricsFromSecurityValidation", metricsFromSecurityValidation);
        metrics.put("pipelineFinished", pipelineFinished);
        metrics.put("sonarLiveAvailable", sonarDisplayAvailable);
        metrics.put("sonarJobFailed", sonarJobFailed);
        metrics.put("secretsEvaluable", secretsEvaluable);
        metrics.put("ddCritical", ddCritical);
        metrics.put("sonarCritical", sonarDisplayAvailable ? sonarCritical : 0);
        metrics.put("combinedCritical", ddCritical + (sonarDisplayAvailable ? sonarCritical : 0));
        SecurityValidationJobState svJobState = securityValidationJobState(execution);
        metrics.put("securityValidationGitlabFailed", svJobState == SecurityValidationJobState.FAILED);
        metrics.put("securityValidationSucceeded", svJobState == SecurityValidationJobState.SUCCESS);

        String ciVerdictRaw = storedGate != null ? stringVal(storedGate.get("verdict")) : null;
        if (ciVerdictRaw == null && storedGate != null) {
            ciVerdictRaw = mapVerdict(stringVal(storedGate.get("recommendation")));
        }
        String ciVerdict = normalizeCiVerdict(ciVerdictRaw);

        int secrets = secretsForMetrics;

        HardGateInput hardGateInput = HardGateInput.builder()
                .secrets(secrets)
                .secretsEvaluable(secretsEvaluable)
                .ddCritical(ddCritical)
                .sonarCritical(sonarCritical)
                .sonarBlockers(sonarBlockers)
                .sonarQgStatus(stringVal(sonarFlat.get("quality_gate_status")))
                .defectDojoAvailable(ddCriticalRes.availableForHardGate())
                .sonarAvailable(sonarDisplayAvailable)
                .build();
        SecurityScoringService.HardGateEvaluation hardGates = securityScoringService.evaluateHardGates(hardGateInput);

        SecurityScoreDto securityScore = null;
        if (hardGates.violations().isEmpty() && hardGates.indeterminateSources().isEmpty()) {
            SecurityScoreInput scoreInput = buildSecurityScoreInput(
                    bySeverity, effectiveSummary, stages, sonarFlat, sonar, storedGate,
                    ddCriticalRes.availableForHardGate(), sonarDisplayAvailable, sonarBlockers, resolvedNcloc);
            securityScore = securityScoringService.computePostureScore(scoreInput);
        }

        VerdictResolution verdictResolution = resolveDeterministicVerdict(hardGates, securityScore);
        String verdict = verdictResolution.verdict();
        String verdictSource = verdictResolution.source();

        List<String> indeterminateSources = new ArrayList<>(hardGates.indeterminateSources());
        if (sonarJobFailed && !indeterminateSources.contains("SonarQube")) {
            indeterminateSources.add("SonarQube");
        }
        String incompleteMessage = buildIncompleteRecommendationMessage(indeterminateSources);
        if (sonarJobFailed) {
            incompleteMessage = SONAR_JOB_FAILED_MSG;
        } else if (metricsFromSecurityValidation && !defectDojoUiAvailable) {
            // Pas de bandeau : les métriques pipeline suffisent, le verdict l'explique déjà.
        }

        List<String> verdictExplanation = buildVerdictExplanation(
                stages, effectiveSummary, bySeverity,
                hardGates.violations(), indeterminateSources, verdict, sonarFlat, securityScore);
        List<String> practicalAdvice = buildPracticalAdvice(verdict, stages, effectiveSummary, toolMetrics, sonarFlat);
        String scoringNote = buildScoringNote();
        String summaryText = buildSummaryText(verdict, bySeverity, stages, securityScore, hardGates, incompleteMessage);

        List<String> availableBranches = mergeAvailableBranches(branch, sonar, dd);

        String pipelineId = execution != null && execution.getGitlabPipelineId() != null
                ? String.valueOf(execution.getGitlabPipelineId())
                : storedGate != null ? stringVal(storedGate.get("pipelineId")) : null;

        String webUrl = null;
        String pipelineStatus = null;
        if (execution != null && execution.getStatus() != null) {
            pipelineStatus = execution.getStatus().name().toLowerCase(Locale.ROOT);
        }
        if (execution != null && execution.getStagesJson() != null) {
            webUrl = stringVal(execution.getStagesJson().get("webUrl"));
            if (pipelineStatus == null) {
                pipelineStatus = stringVal(execution.getStagesJson().get("status"));
            }
        }

        Instant evaluatedAt = null;
        if (storedGate != null && storedGate.get("evaluatedAt") != null) {
            try {
                evaluatedAt = Instant.parse(String.valueOf(storedGate.get("evaluatedAt")));
            } catch (Exception ignored) {
            }
        }
        if (evaluatedAt == null && execution != null && execution.getFinishedAt() != null) {
            evaluatedAt = execution.getFinishedAt().atZone(java.time.ZoneId.systemDefault()).toInstant();
        }

        String source = scopedEnvId != null
                ? (usePipelineSummary ? "pipeline-summary+sonarqube" : "defectdojo-env-tag+sonarqube")
                : (usePipelineSummary
                        ? "pipeline-summary+defectdojo+sonarqube"
                        : (dd != null && dd.isConfigured() ? "defectdojo+sonarqube" : "gitlab-stages"));

        QualityGateResultDto built = QualityGateResultDto.builder()
                .applicationId(app.getId())
                .branch(branch)
                .pipelineId(pipelineId)
                .environmentId(scopedEnvId)
                .evaluatedAt(evaluatedAt)
                .pipelineStatus(pipelineStatus)
                .pipelineWebUrl(webUrl)
                .stages(stages)
                .metrics(metrics)
                .toolMetrics(toolMetrics)
                .thresholds(QualityGateThresholds.asMap())
                .verdict(verdict != null ? verdict : "UNKNOWN")
                .ciVerdict(ciVerdict)
                .verdictSource(verdictSource)
                .securityScore(securityScore)
                .hardGateViolations(hardGates.violations())
                .hardGateIndeterminate(hardGates.indeterminate())
                .hardGateSummary(hardGates.summaryMessage())
                .defectDojoAvailable(defectDojoUiAvailable)
                .metricsFromSecurityValidation(metricsFromSecurityValidation)
                .pipelineFinished(pipelineFinished)
                .canCaptureSnapshot(canPersistSnapshot(execution))
                .indeterminateSources(indeterminateSources)
                .incompleteRecommendationMessage(incompleteMessage)
                .ncloc(resolvedNcloc > 0 ? resolvedNcloc : null)
                .nclocSource(nclocResolution.source())
                .softwareQuality(softwareQuality)
                .softwareQualitySeverity(softwareQualitySeverity)
                .sonarAvailability(sonarAvailability)
                .availableBranches(availableBranches)
                .summary(summaryText)
                .detailedRecommendations(practicalAdvice)
                .verdictExplanation(verdictExplanation)
                .practicalAdvice(practicalAdvice)
                .scoringNote(scoringNote)
                .trendNote(buildTrendNote(dd))
                .source(source)
                .build();
        if (!defectDojoUiAvailable) {
            applyDefectDojoSnapshotFallback(built, execution);
        }
        applyPipelineJobEvaluability(built, execution);
        return built;
    }

    private record DdCriticalResolution(int critical, boolean availableForHardGate) {}

    private DdCriticalResolution resolveDdCritical(
            DefectDojoDashboard2Response dd,
            Map<String, Object> summary,
            Map<String, Object> storedGate,
            PipelineExecution execution
    ) {
        if (isDefectDojoAvailableForQualityGate(dd, execution) && dd != null && dd.getBySeverity() != null) {
            return new DdCriticalResolution(dd.getBySeverity().getOrDefault("Critical", 0), true);
        }
        Map<String, Object> effective = summary != null && !summary.isEmpty()
                ? summary
                : extractSummary(storedGate);
        if (!effective.isEmpty()) {
            return new DdCriticalResolution(pipelineCriticalCount(effective), true);
        }
        if (storedGate != null) {
            int crit = intVal(storedGate.get("critical")) + intVal(storedGate.get("containerCritical"));
            if (crit > 0 || storedGate.get("secrets") != null || storedGate.get("verdict") != null) {
                return new DdCriticalResolution(crit, true);
            }
        }
        return new DdCriticalResolution(0, false);
    }

    /**
     * Affichage centralisation : DefectDojo live si joignable, sinon métriques figées du snapshot
     * (rapport security-validation) sans message « n'a pas répondu ».
     */
    private void finalizeDefectDojoPresentation(
            QualityGateResultDto dto,
            AppService app,
            String branch,
            UUID environmentId,
            PipelineExecution execution
    ) {
        if (dto == null) {
            return;
        }
        tryEnrichFromLiveDefectDojo(dto, app, branch, environmentId, execution);
        if (!Boolean.TRUE.equals(dto.getDefectDojoAvailable())) {
            applyDefectDojoSnapshotFallback(dto, execution);
        }
        applyPipelineJobEvaluability(dto, execution);
    }

    private void tryEnrichFromLiveDefectDojo(
            QualityGateResultDto dto,
            AppService app,
            String branch,
            UUID environmentId,
            PipelineExecution execution
    ) {
        DefectDojoDashboard2Response dd = null;
        try {
            dd = defectDojoService.getDashboard2(app.getId(), branch, environmentId);
        } catch (Exception e) {
            log.debug("DefectDojo live indisponible — fallback snapshot: {}", e.getMessage());
            return;
        }
        if (!isDefectDojoAvailableForQualityGate(dd, execution)) {
            return;
        }
        Map<String, Object> storedGate = execution != null ? execution.getQualityGateJson() : null;
        Map<String, Object> summary = resolveEffectiveSummary(execution, storedGate);
        Map<String, Object> sonarFlat = resolveSonarFlatForPresentation(dto, storedGate, summary);
        boolean hasSummary = !summary.isEmpty();
        boolean preferDdTools = dd.getByTool() != null
                && dd.getByTool().values().stream().anyMatch(v -> v != null && v > 0);
        List<SoftwareQualityDimensionDto> softwareQuality = dto.getSoftwareQuality() != null
                ? dto.getSoftwareQuality()
                : buildSoftwareQualityDimensions(sonarFlat, !sonarFlat.isEmpty());
        List<QualityGateToolMetricDto> tools = buildToolMetrics(
                summary, dd.getByTool(), sonarFlat, !preferDdTools, softwareQuality);
        if (dto.getStages() != null && !dto.getStages().isEmpty()) {
            attachStageToTools(tools, dto.getStages());
        }
        Map<String, Integer> bySeverity = buildBySeverity(dd, summary, tools, true);
        int total = bySeverity.values().stream().mapToInt(Integer::intValue).sum();

        dto.setToolMetrics(tools);
        dto.setDefectDojoAvailable(true);
        dto.setMetricsFromSecurityValidation(false);
        if (dto.getMetrics() == null) {
            dto.setMetrics(new LinkedHashMap<>());
        }
        dto.getMetrics().put("defectDojoAvailable", true);
        dto.getMetrics().put("metricsFromSecurityValidation", false);
        dto.getMetrics().put("bySeverity", bySeverity);
        dto.getMetrics().put("totalVulnerabilities", total);

        DdCriticalResolution ddCriticalRes = resolveDdCritical(dd, summary, storedGate, execution);
        refreshDdHardGateFromCounts(dto, ddCriticalRes.critical(), true);
        stripCentralizationIndeterminate(dto);
        dto.setIncompleteRecommendationMessage(null);
    }

    /** Fallback : données pipeline / snapshot BDD quand DefectDojo (site) est inaccessible. */
    @SuppressWarnings("unchecked")
    private void applyDefectDojoSnapshotFallback(QualityGateResultDto dto, PipelineExecution execution) {
        if (!hasSnapshotPipelineVulnData(dto, execution)) {
            return;
        }
        dto.setDefectDojoAvailable(false);
        dto.setMetricsFromSecurityValidation(true);
        if (dto.getMetrics() == null) {
            dto.setMetrics(new LinkedHashMap<>());
        }
        dto.getMetrics().put("defectDojoAvailable", false);
        dto.getMetrics().put("metricsFromSecurityValidation", true);

        Map<String, Object> storedGate = execution != null ? execution.getQualityGateJson() : null;
        Map<String, Object> summary = resolveEffectiveSummaryForPresentation(dto, execution, storedGate);
        DdCriticalResolution ddCriticalRes = resolveDdCriticalForSnapshot(dto, summary, storedGate, execution);
        refreshDdHardGateFromCounts(dto, ddCriticalRes.critical(), ddCriticalRes.availableForHardGate());
        stripCentralizationIndeterminate(dto);

        if (dto.getToolMetrics() != null && !dto.getToolMetrics().isEmpty()) {
            Map<String, Integer> bySev = aggregateSeverityFromTools(dto.getToolMetrics());
            int total = bySev.values().stream().mapToInt(Integer::intValue).sum();
            dto.getMetrics().put("bySeverity", bySev);
            dto.getMetrics().put("totalVulnerabilities", total);
        }

        if ("INDETERMINE".equals(dto.getVerdict())) {
            String ci = normalizeCiVerdict(dto.getCiVerdict());
            if (ci != null) {
                dto.setVerdict(ci);
                dto.setVerdictSource("HARD_GATES");
            } else if (dto.getHardGateViolations() != null && !dto.getHardGateViolations().isEmpty()) {
                dto.setVerdict("NOT_RECOMMENDED");
                dto.setVerdictSource("HARD_GATES");
            }
        }

        sanitizeSnapshotFallbackMessaging(dto, storedGate);

        Map<String, Object> sonarFlat = resolveSonarFlatForPresentation(dto, storedGate, summary);
        Map<String, Integer> bySev = dto.getMetrics().get("bySeverity") instanceof Map<?, ?> m
                ? (Map<String, Integer>) m
                : Map.of();
        dto.setVerdictExplanation(buildVerdictExplanation(
                dto.getStages() != null ? dto.getStages() : List.of(),
                summary,
                bySev,
                dto.getHardGateViolations(),
                dto.getIndeterminateSources(),
                dto.getVerdict(),
                sonarFlat,
                dto.getSecurityScore()));
    }

    @SuppressWarnings("unchecked")
    private boolean hasSnapshotPipelineVulnData(QualityGateResultDto dto, PipelineExecution execution) {
        if (dto == null) {
            return false;
        }
        if (Boolean.TRUE.equals(dto.getMetricsFromSecurityValidation())) {
            return true;
        }
        if (dto.getMetrics() != null && Boolean.TRUE.equals(dto.getMetrics().get("metricsFromSecurityValidation"))) {
            return true;
        }
        if (dto.getToolMetrics() != null && !dto.getToolMetrics().isEmpty()) {
            return true;
        }
        if (dto.getHardGateViolations() != null && !dto.getHardGateViolations().isEmpty()) {
            return true;
        }
        if (dto.getCiVerdict() != null && !dto.getCiVerdict().isBlank()) {
            return true;
        }
        String verdict = dto.getVerdict();
        if (verdict != null && !"INDETERMINE".equals(verdict) && !"UNKNOWN".equals(verdict)) {
            return true;
        }
        if (dto.getStages() != null && dto.getStages().stream().anyMatch(s -> "PASS".equals(s.getStatus()))) {
            return true;
        }
        if (dto.getMetrics() != null && dto.getMetrics().get("bySeverity") instanceof Map<?, ?> bs) {
            int sum = ((Map<String, Integer>) bs).values().stream().mapToInt(v -> v != null ? v : 0).sum();
            if (sum > 0) {
                return true;
            }
        }
        Map<String, Object> storedGate = execution != null ? execution.getQualityGateJson() : null;
        return !resolveEffectiveSummaryForPresentation(dto, execution, storedGate).isEmpty();
    }

    private Map<String, Object> resolveEffectiveSummaryForPresentation(
            QualityGateResultDto dto,
            PipelineExecution execution,
            Map<String, Object> storedGate
    ) {
        Map<String, Object> summary = resolveEffectiveSummary(execution, storedGate);
        if (!summary.isEmpty()) {
            return summary;
        }
        if (dto == null || dto.getMetrics() == null) {
            return Map.of();
        }
        Map<String, Object> fromMetrics = new LinkedHashMap<>();
        Object secrets = dto.getMetrics().get("secrets");
        if (secrets != null) {
            fromMetrics.put("secrets", secrets);
        }
        if (dto.getMetrics().get("bySeverity") instanceof Map<?, ?> bs && !bs.isEmpty()) {
            Map<String, Object> sca = new LinkedHashMap<>();
            sca.put("critical", intVal(bs.get("critical")));
            sca.put("high", intVal(bs.get("high")));
            sca.put("medium", intVal(bs.get("medium")));
            sca.put("low", intVal(bs.get("low")));
            fromMetrics.put("sca", sca);
        }
        return fromMetrics.isEmpty() ? Map.of() : fromMetrics;
    }

    private DdCriticalResolution resolveDdCriticalForSnapshot(
            QualityGateResultDto dto,
            Map<String, Object> summary,
            Map<String, Object> storedGate,
            PipelineExecution execution
    ) {
        DdCriticalResolution base = resolveDdCritical(null, summary, storedGate, execution);
        if (base.availableForHardGate()) {
            return base;
        }
        if (hasSnapshotPipelineVulnData(dto, execution)) {
            return new DdCriticalResolution(criticalFromToolMetrics(dto), true);
        }
        return base;
    }

    private int criticalFromToolMetrics(QualityGateResultDto dto) {
        if (dto == null || dto.getToolMetrics() == null) {
            return 0;
        }
        return dto.getToolMetrics().stream()
                .mapToInt(QualityGateToolMetricDto::getCritical)
                .sum();
    }

    private void sanitizeSnapshotFallbackMessaging(QualityGateResultDto dto, Map<String, Object> storedGate) {
        dto.setIncompleteRecommendationMessage(null);
        String summary = dto.getSummary();
        if (summary == null) {
            return;
        }
        String lower = summary.toLowerCase(Locale.ROOT);
        boolean staleInfraMsg = lower.contains("n'a pas répondu")
                || lower.contains("n'a/ont pas répondu")
                || (lower.contains("recommandation incomplète") && lower.contains("centralisation"))
                || lower.contains("centralisation des vulnérabilités indisponible");
        if (!staleInfraMsg) {
            return;
        }
        if (dto.getHardGateSummary() != null && !dto.getHardGateSummary().isBlank()) {
            dto.setSummary(dto.getHardGateSummary());
        } else if (storedGate != null && storedGate.get("recommendation") != null) {
            dto.setSummary("Verdict pipeline : " + storedGate.get("recommendation"));
        } else if (dto.getCiVerdict() != null) {
            dto.setSummary("Verdict pipeline : " + dto.getCiVerdict());
        }
    }

    private void stripCentralizationIndeterminate(QualityGateResultDto dto) {
        if (dto.getIndeterminateSources() != null) {
            dto.setIndeterminateSources(dto.getIndeterminateSources().stream()
                    .filter(s -> !isCentralizationSource(s))
                    .toList());
        }
        if (dto.getHardGateIndeterminate() != null) {
            dto.setHardGateIndeterminate(dto.getHardGateIndeterminate().stream()
                    .filter(v -> !"dd_critical".equals(v.getId()))
                    .toList());
        }
    }

    private boolean isCentralizationSource(String source) {
        return source != null && source.toLowerCase(Locale.ROOT).contains("centralisation");
    }

    private void refreshDdHardGateFromCounts(QualityGateResultDto dto, int ddCriticalOnly, boolean evaluable) {
        if (!evaluable) {
            return;
        }
        int sonarCrit = sonarCriticalCountFromDto(dto);
        int combined = ddCriticalOnly + sonarCrit;
        List<HardGateViolationDto> violations = dto.getHardGateViolations() != null
                ? new ArrayList<>(dto.getHardGateViolations())
                : new ArrayList<>();
        violations.removeIf(v -> "dd_critical".equals(v.getId()));
        if (combined > 0) {
            String message = combined + " vulnérabilité(s) critique(s)";
            if (sonarCrit > 0 && ddCriticalOnly > 0) {
                message += " (centralisation " + ddCriticalOnly + " + SonarQube " + sonarCrit + ")";
            } else if (sonarCrit > 0) {
                message += " (SonarQube " + sonarCrit + ")";
            }
            violations.add(HardGateViolationDto.builder()
                    .id("dd_critical")
                    .label("Vulnérabilités critiques")
                    .message(message)
                    .status("VIOLATED")
                    .build());
        }
        dto.setHardGateViolations(violations);
        if (dto.getMetrics() == null) {
            dto.setMetrics(new LinkedHashMap<>());
        }
        dto.getMetrics().put("ddCritical", ddCriticalOnly);
        dto.getMetrics().put("sonarCritical", sonarCrit);
        dto.getMetrics().put("combinedCritical", combined);
        stripCentralizationIndeterminate(dto);
    }

    private int sonarCriticalCountFromDto(QualityGateResultDto dto) {
        if (dto == null) {
            return 0;
        }
        if (dto.getMetrics() != null) {
            Object stored = dto.getMetrics().get("sonarCritical");
            if (stored != null) {
                return intVal(stored);
            }
            Object sq = dto.getMetrics().get("sonarQube");
            if (sq instanceof Map<?, ?> sonarMap) {
                Object bs = sonarMap.get("bySeverity");
                if (bs instanceof Map<?, ?> sev) {
                    return intVal(sev.get("critical"));
                }
            }
        }
        if (dto.getToolMetrics() != null) {
            for (QualityGateToolMetricDto tool : dto.getToolMetrics()) {
                if ("sonarqube".equals(tool.getId())) {
                    return tool.getHigh();
                }
            }
        }
        return 0;
    }

    private void refreshCombinedCriticalHardGate(QualityGateResultDto dto) {
        if (dto == null || dto.getMetrics() == null) {
            return;
        }
        boolean evaluable = Boolean.TRUE.equals(dto.getDefectDojoAvailable())
                || Boolean.TRUE.equals(dto.getMetricsFromSecurityValidation());
        if (!evaluable) {
            return;
        }
        int ddCrit = 0;
        Object bs = dto.getMetrics().get("bySeverity");
        if (bs instanceof Map<?, ?> sev) {
            ddCrit = intVal(sev.get("critical"));
        }
        refreshDdHardGateFromCounts(dto, ddCrit, true);
    }

    private int pipelineCriticalCount(Map<String, Object> summary) {
        Map<String, Object> sca = mapVal(summary, "sca");
        Map<String, Object> container = mapVal(summary, "container");
        return intVal(sca.get("critical")) + intVal(container.get("critical"));
    }

    private record VerdictResolution(String verdict, String source) {}

    private QualityGateResultDto buildMissingSnapshotResult(
            AppService app,
            String branch,
            UUID environmentId,
            PipelineExecution execution
    ) {
        String pipelineId = execution != null && execution.getGitlabPipelineId() != null
                ? String.valueOf(execution.getGitlabPipelineId()) : null;
        String pipelineStatus = execution != null && execution.getStatus() != null
                ? execution.getStatus().name() : null;
        String tag = DefectDojoService.environmentTag(environmentId);
        boolean running = execution != null && execution.getStatus() != null && !execution.getStatus().isFinished();
        int jobCount = countJobsInStagesJson(execution);
        String summary;
        String verdict;
        String verdictSource;
        String incompleteMsg = null;
        if (running) {
            verdict = "INDETERMINE";
            verdictSource = "PIPELINE_IN_PROGRESS";
            summary = "Pipeline"
                    + (pipelineId != null ? " #" + pipelineId : "")
                    + " en cours — les stages et le quality gate seront disponibles après la fin des scans.";
            incompleteMsg = "Pipeline en cours — données partielles, ne pas déployer sur cette base.";
        } else if (jobCount <= 0 && execution != null) {
            verdict = "UNKNOWN";
            verdictSource = "SNAPSHOT_MISSING";
            summary = "Aucun snapshot pour cet environnement (tag « " + tag + " ») et aucun job GitLab synchronisé. "
                    + "Lancez un pipeline puis cliquez « Actualiser ».";
        } else {
            verdict = "UNKNOWN";
            verdictSource = "SNAPSHOT_MISSING";
            summary = "Aucun snapshot conservé pour cet environnement (tag DefectDojo « "
                    + tag + " »). "
                    + "Utilisez « Actualiser » ou POST /api/quality-gate/snapshots/backfill pour reconstruire depuis les APIs.";
        }
        QualityGateResultDto.QualityGateResultDtoBuilder builder = QualityGateResultDto.builder()
                .applicationId(app.getId())
                .branch(branch)
                .environmentId(environmentId)
                .pipelineId(pipelineId)
                .pipelineStatus(pipelineStatus)
                .verdict(verdict)
                .verdictSource(verdictSource)
                .incompleteRecommendationMessage(incompleteMsg)
                .fromSnapshot(false)
                .stages(List.of())
                .toolMetrics(List.of())
                .metrics(Map.of(
                        "totalVulnerabilities", 0,
                        "bySeverity", Map.of("critical", 0, "high", 0, "medium", 0, "low", 0, "info", 0),
                        "failedStages", 0,
                        "blockingStages", 0,
                        "warningStages", 0
                ))
                .summary(summary)
                .detailedRecommendations(List.of())
                .practicalAdvice(List.of())
                .verdictExplanation(List.of())
                .availableBranches(listBranches(app.getId()))
                .source("snapshot-missing");
        if (running) {
            builder
                    .hardGateViolations(List.of())
                    .hardGateIndeterminate(pipelinePendingHardGates())
                    .indeterminateSources(List.of("Pipeline"))
                    .defectDojoAvailable(false)
                    .sonarAvailability(SonarAvailabilityDto.builder()
                            .available(false)
                            .message(PIPELINE_PENDING_GATE_MSG)
                            .build());
            if (execution != null && jobCount > 0) {
                Map<String, Object> storedGate = execution.getQualityGateJson();
                Map<String, Object> sum = resolveEffectiveSummary(execution, storedGate);
                List<Map<String, Object>> jobs = getJobsFromStagesJson(execution);
                builder.stages(buildStages(jobs, sum, storedGate, Map.of(), !sum.isEmpty()));
                builder.canCaptureSnapshot(canPersistSnapshot(execution));
            }
        }
        return builder.build();
    }

    private QualityGateResultDto buildMissingSnapshotResultForBranch(
            AppService app,
            String branch,
            PipelineExecution execution
    ) {
        String pipelineId = execution != null && execution.getGitlabPipelineId() != null
                ? String.valueOf(execution.getGitlabPipelineId()) : null;
        String branchLabel = branch != null ? branch : "toutes branches";
        return QualityGateResultDto.builder()
                .applicationId(app.getId())
                .branch(branch)
                .pipelineId(pipelineId)
                .pipelineStatus(execution != null && execution.getStatus() != null
                        ? execution.getStatus().name() : null)
                .verdict("UNKNOWN")
                .verdictSource("SNAPSHOT_MISSING")
                .fromSnapshot(false)
                .stages(List.of())
                .toolMetrics(List.of())
                .metrics(Map.of(
                        "totalVulnerabilities", 0,
                        "bySeverity", Map.of("critical", 0, "high", 0, "medium", 0, "low", 0, "info", 0),
                        "failedStages", 0,
                        "blockingStages", 0,
                        "warningStages", 0
                ))
                .summary("Aucun snapshot en base pour la branche « " + branchLabel + " ». "
                        + "Cliquez « Actualiser » pour reconstruire depuis DefectDojo/Sonar, "
                        + "ou POST /api/quality-gate/snapshots/backfill.")
                .detailedRecommendations(List.of())
                .practicalAdvice(List.of())
                .verdictExplanation(List.of())
                .availableBranches(listBranches(app.getId()))
                .source("snapshot-missing")
                .build();
    }

    private PipelineExecution findLatestExecution(UUID applicationId, String branch) {
        List<PipelineExecution> list = pipelineExecutionRepository
                .findByApplicationIdAndBranchOrderByCreatedAtDesc(applicationId, branch, PageRequest.of(0, 1));
        return list.isEmpty() ? null : list.get(0);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> extractSummary(Map<String, Object> storedGate) {
        if (storedGate == null) return Map.of();
        Object summary = storedGate.get("summary");
        if (summary instanceof Map<?, ?> m) {
            return (Map<String, Object>) m;
        }
        return Map.of();
    }

    /** summary.json du pipeline, métriques CI security-validation, sinon findings BDD. */
    private Map<String, Object> resolveEffectiveSummary(
            PipelineExecution execution,
            Map<String, Object> storedGate
    ) {
        Map<String, Object> fromGate = extractSummary(storedGate);
        if (!fromGate.isEmpty()) {
            return fromGate;
        }
        Map<String, Object> fromCiIngest = buildSummaryFromStoredGate(storedGate);
        if (!fromCiIngest.isEmpty()) {
            return fromCiIngest;
        }
        if (execution != null && execution.getGitlabPipelineId() != null) {
            Map<String, Object> fromFindings = buildSummaryFromPipelineFindings(execution.getGitlabPipelineId());
            if (!fromFindings.isEmpty()) {
                return fromFindings;
            }
        }
        return Map.of();
    }

    /** Reconstruit summary.json à partir des champs plats POST /api/security-gate. */
    @SuppressWarnings("unchecked")
    private Map<String, Object> synthesizeSummaryFromIngest(SecurityGateIngestRequest request) {
        if (request.getSummary() != null && !request.getSummary().isNull()) {
            return objectMapper.convertValue(request.getSummary(), Map.class);
        }
        if (request.getRecommendation() == null && request.getCritical() == null && request.getHigh() == null
                && request.getSecrets() == null && request.getContainerCritical() == null
                && request.getSemgrepHigh() == null) {
            return Map.of();
        }
        Map<String, Object> summary = new LinkedHashMap<>();
        Map<String, Object> sca = new LinkedHashMap<>();
        putIfNotNull(sca, "critical", request.getCritical());
        putIfNotNull(sca, "high", request.getHigh());
        putIfNotNull(sca, "medium", request.getScaMedium());
        putIfNotNull(sca, "low", request.getScaLow());
        summary.put("sca", sca);

        Map<String, Object> container = new LinkedHashMap<>();
        putIfNotNull(container, "critical", request.getContainerCritical());
        putIfNotNull(container, "high", request.getContainerHigh());
        summary.put("container", container);

        putIfNotNull(summary, "secrets", request.getSecrets());

        Map<String, Object> sast = new LinkedHashMap<>();
        putIfNotNull(sast, "semgrep_high", request.getSemgrepHigh());
        putIfNotNull(sast, "semgrep_medium", request.getSemgrepMedium());
        putIfNotNull(sast, "semgrep_info", request.getSemgrepInfo());
        putIfNotNull(sast, "hadolint_errors", request.getHadolintErrors());
        summary.put("sast", sast);

        Map<String, Object> iac = new LinkedHashMap<>();
        putIfNotNull(iac, "checkov_failed", request.getCheckovFailed());
        summary.put("iac", iac);

        Map<String, Object> dast = new LinkedHashMap<>();
        putIfNotNull(dast, "high", request.getDastHigh());
        putIfNotNull(dast, "medium", request.getDastMedium());
        putIfNotNull(dast, "low", request.getDastLow());
        summary.put("dast", dast);

        if (request.getSonarQualityGate() != null || request.getSonarBlockers() != null) {
            Map<String, Object> sonar = new LinkedHashMap<>();
            if (request.getSonarQualityGate() != null) {
                sonar.put("quality_gate", request.getSonarQualityGate().trim());
            }
            putIfNotNull(sonar, "blocker_violations", request.getSonarBlockers());
            putIfNotNull(sonar, "critical_violations", request.getSonarCriticals());
            putIfNotNull(sonar, "bugs", request.getSonarBugs());
            putIfNotNull(sonar, "vulnerabilities", request.getSonarVulnerabilities());
            putIfNotNull(sonar, "hotspots", request.getSonarHotspots());
            summary.put("sonar", sonar);
        }
        summary.put("source", "ci-ingest");
        return summary;
    }

    private void putIfNotNull(Map<String, Object> target, String key, Integer value) {
        if (value != null) {
            target.put(key, value);
        }
    }

    /** Fallback quand summary.json n'est pas encore dans quality_gate_json mais l'ingest CI a tourné. */
    @SuppressWarnings("unchecked")
    private Map<String, Object> buildSummaryFromStoredGate(Map<String, Object> storedGate) {
        if (storedGate == null || storedGate.isEmpty()) {
            return Map.of();
        }
        Object nested = storedGate.get("summary");
        if (nested instanceof Map<?, ?> m && !m.isEmpty()) {
            return (Map<String, Object>) m;
        }
        boolean hasCiMarker = storedGate.get("verdict") != null
                || storedGate.get("recommendation") != null
                || storedGate.get("evaluatedAt") != null;
        if (!hasCiMarker && storedGate.get("critical") == null && storedGate.get("secrets") == null) {
            return Map.of();
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        Map<String, Object> sca = new LinkedHashMap<>();
        sca.put("critical", intVal(storedGate.get("critical")));
        sca.put("high", intVal(storedGate.get("high")));
        sca.put("medium", intVal(storedGate.get("scaMedium")));
        summary.put("sca", sca);

        Map<String, Object> container = new LinkedHashMap<>();
        container.put("critical", intVal(storedGate.get("containerCritical")));
        container.put("high", intVal(storedGate.get("containerHigh")));
        summary.put("container", container);

        summary.put("secrets", intVal(storedGate.get("secrets")));

        Map<String, Object> sast = new LinkedHashMap<>();
        sast.put("semgrep_high", intVal(storedGate.get("semgrepHigh")));
        sast.put("semgrep_medium", intVal(storedGate.get("semgrepMedium")));
        summary.put("sast", sast);

        Map<String, Object> iac = new LinkedHashMap<>();
        iac.put("checkov_failed", intVal(storedGate.get("checkovFailed")));
        summary.put("iac", iac);

        Map<String, Object> dast = new LinkedHashMap<>();
        dast.put("high", intVal(storedGate.get("dastHigh")));
        summary.put("dast", dast);
        summary.put("source", "stored-gate-fields");
        return summary;
    }

    private Map<String, Object> buildSummaryFromPipelineFindings(Long gitlabPipelineId) {
        if (gitlabPipelineId == null) {
            return Map.of();
        }
        List<Object[]> rows = findingOccurrenceRepository
                .countDistinctFindingsByToolAndSeverityForPipeline(gitlabPipelineId);
        if (rows == null || rows.isEmpty()) {
            return Map.of();
        }

        Map<String, Object> sca = new LinkedHashMap<>();
        Map<String, Object> container = new LinkedHashMap<>();
        Map<String, Object> sast = new LinkedHashMap<>();
        Map<String, Object> dast = new LinkedHashMap<>();
        Map<String, Object> iac = new LinkedHashMap<>();
        int secrets = 0;

        for (Object[] row : rows) {
            String tool = row[0] != null ? String.valueOf(row[0]).toLowerCase(Locale.ROOT) : "";
            String severity = row[1] != null ? String.valueOf(row[1]).toUpperCase(Locale.ROOT) : "";
            int count = row[2] instanceof Number n ? n.intValue() : 0;
            if (count <= 0 || tool.isBlank()) continue;

            if (tool.contains("trivy")) {
                addSeverityCount(sca, severity, count);
            } else if (tool.contains("grype") || tool.contains("container")) {
                addSeverityCount(container, severity, count);
            } else if (tool.contains("semgrep")) {
                if ("HIGH".equals(severity) || "CRITICAL".equals(severity)) {
                    sast.put("semgrep_high", intVal(sast.get("semgrep_high")) + count);
                } else if ("MEDIUM".equals(severity)) {
                    sast.put("semgrep_medium", intVal(sast.get("semgrep_medium")) + count);
                } else if ("INFO".equals(severity) || "LOW".equals(severity)) {
                    sast.put("semgrep_info", intVal(sast.get("semgrep_info")) + count);
                }
            } else if (tool.contains("gitleaks") || tool.contains("secret")) {
                secrets += count;
            } else if (tool.contains("checkov") || tool.contains("iac")) {
                iac.put("checkov_failed", intVal(iac.get("checkov_failed")) + count);
            } else if (tool.contains("zap") || tool.contains("dast")) {
                addSeverityCount(dast, severity, count);
            } else if (tool.contains("hadolint")) {
                sast.put("hadolint_errors", intVal(sast.get("hadolint_errors")) + count);
            }
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("sca", sca);
        summary.put("container", container);
        summary.put("sast", sast);
        summary.put("dast", dast);
        summary.put("iac", iac);
        summary.put("secrets", secrets);
        summary.put("source", "finding-occurrences");
        return summary;
    }

    private void addSeverityCount(Map<String, Object> bucket, String severity, int count) {
        switch (severity) {
            case "CRITICAL" -> bucket.put("critical", intVal(bucket.get("critical")) + count);
            case "HIGH" -> bucket.put("high", intVal(bucket.get("high")) + count);
            case "MEDIUM" -> bucket.put("medium", intVal(bucket.get("medium")) + count);
            case "LOW", "INFO" -> bucket.put("low", intVal(bucket.get("low")) + count);
            default -> bucket.put("high", intVal(bucket.get("high")) + count);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> sonarFlatMetrics(Map<String, Object> sonar) {
        if (sonar == null) return Map.of();
        Object nested = sonar.get("metrics");
        Map<String, Object> flat = new LinkedHashMap<>();
        if (nested instanceof Map<?, ?> m) {
            flat.putAll((Map<String, Object>) m);
        } else {
            flat.putAll(sonar);
        }
        Object qg = sonar.get("quality_gate");
        if (qg instanceof Map<?, ?> qgm) {
            flat.put("quality_gate", qgm);
            Object status = qgm.get("status");
            if (status != null) {
                flat.put("quality_gate_status", status);
            }
            Object conditions = qgm.get("conditions");
            if (conditions instanceof List<?> list) {
                long failed = list.stream()
                        .filter(c -> c instanceof Map<?, ?> cond
                                && "ERROR".equalsIgnoreCase(String.valueOf(cond.get("status"))))
                        .count();
                flat.put("quality_gate_failed_conditions", failed);
            }
        }
        if (sonar.get("total_hotspots") != null) {
            putIfZero(flat, "security_hotspots", sonar.get("total_hotspots"));
        }
        if (sonar.get("branch") != null) {
            flat.put("sonar_branch", sonar.get("branch"));
        }
        if (sonar.get("software_quality_severity") instanceof Map<?, ?> sqSev) {
            flat.put("software_quality_severity", sqSev);
        }
        applySoftwareQualityDimensionsToFlat(flat, sonar.get("software_quality_dimensions"));
        if (flat.get("software_quality_dimensions") instanceof List<?> dims) {
            applySoftwareQualityDimensionsToFlat(flat, dims);
        }
        if (flat.get("by_severity") == null && sonar.get("bySeverity") instanceof Map<?, ?> camelSev) {
            flat.put("by_severity", camelSev);
        }
        Object bySev = flat.get("by_severity");
        if (bySev == null && sonar.get("open_issues_by_severity") instanceof Map<?, ?> m) {
            flat.put("by_severity", m);
        }
        return flat;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Integer> sonarSeverityFromMetricsMap(Map<String, Object> sonarQubeMetrics) {
        if (sonarQubeMetrics == null || sonarQubeMetrics.isEmpty()) {
            return Map.of();
        }
        Object bs = sonarQubeMetrics.get("bySeverity");
        if (bs == null) {
            bs = sonarQubeMetrics.get("by_severity");
        }
        if (!(bs instanceof Map<?, ?> m)) {
            return Map.of();
        }
        Map<String, Integer> out = new LinkedHashMap<>();
        m.forEach((k, v) -> out.put(String.valueOf(k).toLowerCase(Locale.ROOT), intVal(v)));
        return out;
    }

    private void refreshSonarToolMetric(
            List<QualityGateToolMetricDto> tools,
            Map<String, Object> sonarFlat,
            List<SoftwareQualityDimensionDto> softwareQuality,
            Map<String, Object> metricsSonarQube
    ) {
        if (tools == null || tools.isEmpty()) {
            return;
        }
        Map<String, Integer> sev = !sonarFlat.isEmpty()
                ? sonarViolationBySeverity(sonarFlat)
                : sonarSeverityFromMetricsMap(metricsSonarQube);
        if (sev.values().stream().allMatch(v -> v == 0) && softwareQuality != null) {
            for (SoftwareQualityDimensionDto dim : softwareQuality) {
                if (dim.getBySeverity() == null || dim.getBySeverity().isEmpty()) {
                    continue;
                }
                if ("SECURITY".equalsIgnoreCase(dim.getDimension())) {
                    Map<String, Integer> merged = new LinkedHashMap<>(sev);
                    dim.getBySeverity().forEach((k, v) -> {
                        String key = k.toLowerCase(Locale.ROOT);
                        if ("high".equals(key)) {
                            merged.merge("major", v != null ? v : 0, Integer::sum);
                        } else if ("medium".equals(key)) {
                            merged.merge("minor", v != null ? v : 0, Integer::sum);
                        } else {
                            merged.merge(key, v != null ? v : 0, Integer::sum);
                        }
                    });
                    sev = merged;
                    break;
                }
            }
        }
        int blocker = sev.getOrDefault("blocker", 0);
        int critical = sev.getOrDefault("critical", 0);
        int major = sev.getOrDefault("major", 0);
        int minor = sev.getOrDefault("minor", 0);
        if (blocker + critical + major + minor == 0) {
            return;
        }
        for (int i = 0; i < tools.size(); i++) {
            QualityGateToolMetricDto t = tools.get(i);
            if (!"sonarqube".equals(t.getId())) {
                continue;
            }
            int total = computeSonarTotalIssues(sonarFlat, softwareQuality);
            if (total <= 0) {
                total = blocker + critical + major + minor;
            }
            tools.set(i, t.toBuilder()
                    .critical(blocker)
                    .high(critical)
                    .medium(major)
                    .low(minor)
                    .total(total)
                    .raw(!sonarFlat.isEmpty() ? sonarFlat : t.getRaw())
                    .build());
            return;
        }
    }

    private void refreshSonarToolMetric(QualityGateResultDto dto, Map<String, Object> sonarFlat) {
        if (dto == null || dto.getToolMetrics() == null) {
            return;
        }
        Map<String, Object> metricsSonar = null;
        if (dto.getMetrics() != null && dto.getMetrics().get("sonarQube") instanceof Map<?, ?> sq) {
            @SuppressWarnings("unchecked")
            Map<String, Object> cast = (Map<String, Object>) sq;
            metricsSonar = cast;
        }
        refreshSonarToolMetric(
                dto.getToolMetrics(),
                sonarFlat != null ? sonarFlat : Map.of(),
                dto.getSoftwareQuality(),
                metricsSonar);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Integer> sonarViolationBySeverity(Map<String, Object> sonarFlat) {
        Object bySev = sonarFlat.get("by_severity");
        if (bySev instanceof Map<?, ?> m) {
            Map<String, Integer> out = new LinkedHashMap<>();
            m.forEach((k, v) -> out.put(String.valueOf(k), intVal(v)));
            return out;
        }
        Map<String, Integer> built = new LinkedHashMap<>();
        built.put("blocker", intVal(sonarFlat.get("blocker_violations")));
        built.put("critical", intVal(sonarFlat.get("critical_violations")));
        built.put("major", intVal(sonarFlat.get("major_violations")));
        built.put("minor", intVal(sonarFlat.get("minor_violations")));
        built.put("info", intVal(sonarFlat.get("info_violations")));
        return built;
    }

    private int sonarViolationCount(Map<String, Object> sonarFlat, String key) {
        return sonarViolationBySeverity(sonarFlat).getOrDefault(key, 0);
    }

    private void putIfZero(Map<String, Object> map, String key, Object value) {
        if (value == null) return;
        Object existing = map.get(key);
        if (existing == null || "0".equals(String.valueOf(existing))) {
            map.put(key, value);
        }
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> getJobsFromStagesJson(PipelineExecution execution) {
        Map<String, Object> stages = execution.getStagesJson();
        if (stages == null) {
            return List.of();
        }
        Object jobs = stages.get("jobs");
        if (jobs instanceof List) {
            return (List<Map<String, Object>>) jobs;
        }
        return List.of();
    }

    private Map<String, Integer> aggregateSeverityFromTools(List<QualityGateToolMetricDto> tools) {
        Map<String, Integer> out = new LinkedHashMap<>();
        out.put("critical", 0);
        out.put("high", 0);
        out.put("medium", 0);
        out.put("low", 0);
        out.put("info", 0);
        if (tools == null) {
            return out;
        }
        for (QualityGateToolMetricDto t : tools) {
            if ("sonarqube".equals(t.getId())) {
                continue;
            }
            out.put("critical", out.get("critical") + t.getCritical());
            out.put("high", out.get("high") + t.getHigh());
            out.put("medium", out.get("medium") + t.getMedium());
            out.put("low", out.get("low") + t.getLow());
        }
        return out;
    }

    private Map<String, Integer> buildBySeverity(
            DefectDojoDashboard2Response dd,
            Map<String, Object> summary,
            List<QualityGateToolMetricDto> tools,
            boolean defectDojoAvailable
    ) {
        Map<String, Integer> out = new LinkedHashMap<>();
        out.put("critical", 0);
        out.put("high", 0);
        out.put("medium", 0);
        out.put("low", 0);
        out.put("info", 0);

        if (defectDojoAvailable && dd != null && dd.getBySeverity() != null && !dd.getBySeverity().isEmpty()) {
            out.put("critical", dd.getBySeverity().getOrDefault("Critical", 0));
            out.put("high", dd.getBySeverity().getOrDefault("High", 0));
            out.put("medium", dd.getBySeverity().getOrDefault("Medium", 0));
            out.put("low", dd.getBySeverity().getOrDefault("Low", 0));
            out.put("info", dd.getBySeverity().getOrDefault("Info", 0));
            return out;
        }

        if (tools != null && !tools.isEmpty()) {
            return aggregateSeverityFromTools(tools);
        }

        if (!summary.isEmpty()) {
            Map<String, Object> sca = mapVal(summary, "sca");
            Map<String, Object> container = mapVal(summary, "container");
            Map<String, Object> sast = mapVal(summary, "sast");
            Map<String, Object> dast = mapVal(summary, "dast");
            int secrets = intVal(summary.get("secrets"));
            out.put("critical", intVal(sca.get("critical")) + intVal(container.get("critical")) + secrets);
            out.put("high", intVal(sca.get("high")) + intVal(container.get("high"))
                    + intVal(sast.get("semgrep_high")) + intVal(dast.get("high")));
            out.put("medium", intVal(sca.get("medium")) + intVal(sast.get("semgrep_medium")) + intVal(dast.get("medium")));
            out.put("low", intVal(sca.get("low")) + intVal(dast.get("low")));
            return out;
        }

        return out;
    }

    private List<QualityGateToolMetricDto> buildToolMetrics(
            Map<String, Object> summary,
            Map<String, Integer> ddByTool,
            Map<String, Object> sonarFlat,
            boolean hasSummary,
            List<SoftwareQualityDimensionDto> softwareQuality
    ) {
        List<QualityGateToolMetricDto> tools = new ArrayList<>();
        Map<String, Object> sca = mapVal(summary, "sca");
        Map<String, Object> container = mapVal(summary, "container");
        Map<String, Object> sast = mapVal(summary, "sast");
        Map<String, Object> dast = mapVal(summary, "dast");
        Map<String, Object> iac = mapVal(summary, "iac");

        int scaCrit = hasSummary ? intVal(sca.get("critical")) : 0;
        int scaHigh = hasSummary ? intVal(sca.get("high")) : 0;
        int scaMed = hasSummary ? intVal(sca.get("medium")) : 0;
        int scaLow = hasSummary ? intVal(sca.get("low")) : 0;
        if (!hasSummary) {
            int ddTotal = countByToolMatchers(ddByTool, "trivy");
            scaHigh = ddTotal;
        }

        tools.add(QualityGateToolMetricDto.builder()
                .id("trivy").label("Trivy FS").type("SCA")
                .critical(scaCrit).high(scaHigh).medium(scaMed).low(scaLow)
                .total(scaCrit + scaHigh + scaMed + scaLow)
                .raw(sca).build());

        int semHigh = hasSummary ? intVal(sast.get("semgrep_high")) : countByToolMatchers(ddByTool, "semgrep");
        int semMed = hasSummary ? intVal(sast.get("semgrep_medium")) : 0;
        tools.add(QualityGateToolMetricDto.builder()
                .id("semgrep").label("Semgrep").type("SAST")
                .critical(0).high(semHigh).medium(semMed).low(0)
                .total(semHigh + semMed)
                .raw(sast).build());

        int secrets = hasSummary ? intVal(summary.get("secrets")) : countByToolMatchers(ddByTool, "gitleaks", "secret");
        tools.add(QualityGateToolMetricDto.builder()
                .id("gitleaks").label("Gitleaks").type("Secrets")
                .critical(0)
                .high(secrets > 0 ? secrets : 0)
                .medium(0).low(0)
                .total(secrets)
                .build());

        int contCrit = hasSummary ? intVal(container.get("critical")) : 0;
        int contHigh = hasSummary ? intVal(container.get("high")) : countByToolMatchers(ddByTool, "grype", "container");
        tools.add(QualityGateToolMetricDto.builder()
                .id("grype").label("Grype").type("Container")
                .critical(contCrit).high(contHigh).medium(0).low(0)
                .total(contCrit + contHigh)
                .raw(container).build());

        int checkov = hasSummary ? intVal(iac.get("checkov_failed")) : countByToolMatchers(ddByTool, "checkov");
        tools.add(QualityGateToolMetricDto.builder()
                .id("checkov").label("Checkov").type("IaC")
                .critical(0).high(checkov).medium(0).low(0)
                .total(checkov)
                .raw(iac).build());

        int dastHigh = hasSummary ? intVal(dast.get("high")) : countByToolMatchers(ddByTool, "zap", "dast");
        int dastMed = hasSummary ? intVal(dast.get("medium")) : 0;
        tools.add(QualityGateToolMetricDto.builder()
                .id("zap").label("OWASP ZAP").type("DAST")
                .critical(0).high(dastHigh).medium(dastMed).low(intVal(dast.get("low")))
                .total(dastHigh + dastMed)
                .raw(dast).build());

        int hadolint = hasSummary ? intVal(sast.get("hadolint_errors")) : countByToolMatchers(ddByTool, "hadolint");
        tools.add(QualityGateToolMetricDto.builder()
                .id("hadolint").label("Hadolint").type("Lint")
                .critical(0).high(hadolint).medium(0).low(0)
                .total(hadolint)
                .build());

        int sonarBlocker = sonarViolationCount(sonarFlat, "blocker");
        int sonarCritical = sonarViolationCount(sonarFlat, "critical");
        int sonarMajor = sonarViolationCount(sonarFlat, "major");
        int sonarMinor = sonarViolationCount(sonarFlat, "minor");
        int sonarTotal = computeSonarTotalIssues(sonarFlat, softwareQuality);
        tools.add(QualityGateToolMetricDto.builder()
                .id("sonarqube").label("SonarQube").type("SAST")
                .critical(sonarBlocker).high(sonarCritical).medium(sonarMajor).low(sonarMinor)
                .total(sonarTotal)
                .raw(sonarFlat).build());

        return tools;
    }

    private int computeSonarTotalIssues(
            Map<String, Object> sonarFlat,
            List<SoftwareQualityDimensionDto> softwareQuality
    ) {
        if (sonarFlat == null || sonarFlat.isEmpty()) {
            return softwareQuality != null
                    ? softwareQuality.stream().mapToInt(SoftwareQualityDimensionDto::getIssues).sum()
                    : 0;
        }
        int totalIssues = intVal(sonarFlat.get("total_issues"));
        if (totalIssues > 0) return totalIssues;

        int openIssues = intVal(sonarFlat.get("open_issues"));
        if (openIssues > 0) return openIssues;

        int sevSum = sonarViolationBySeverity(sonarFlat).values().stream().mapToInt(Integer::intValue).sum();
        if (sevSum > 0) return sevSum;

        int classic = intVal(sonarFlat.get("bugs"))
                + intVal(sonarFlat.get("vulnerabilities"))
                + intVal(sonarFlat.get("code_smells"));
        if (classic > 0) return classic;

        if (softwareQuality != null && !softwareQuality.isEmpty()) {
            int sqSum = softwareQuality.stream().mapToInt(SoftwareQualityDimensionDto::getIssues).sum();
            if (sqSum > 0) return sqSum;
        }

        return intVal(sonarFlat.get("software_quality_security_issues"))
                + intVal(sonarFlat.get("software_quality_reliability_issues"))
                + intVal(sonarFlat.get("software_quality_maintainability_issues"));
    }

    private void attachStageToTools(List<QualityGateToolMetricDto> tools, List<QualityGateStageDto> stages) {
        if (tools == null || stages == null) return;
        for (QualityGateToolMetricDto tool : tools) {
            QualityGateStageDto stage = findStageForTool(tool.getId(), stages);
            if (stage == null) continue;
            tool.setStageStatus(stage.getStatus());
            tool.setStageName(stage.getName());
            tool.setStageLabel(stage.getToolLabel());
        }
    }

    private QualityGateStageDto findStageForTool(String toolId, List<QualityGateStageDto> stages) {
        List<String> matchers = TOOL_STAGE_MATCHERS.get(toolId);
        if (matchers == null || matchers.isEmpty()) return null;
        QualityGateStageDto best = null;
        int bestScore = -1;
        for (QualityGateStageDto stage : stages) {
            String key = stage.getName() != null ? stage.getName().toLowerCase(Locale.ROOT) : "";
            for (String matcher : matchers) {
                if (key.equals(matcher) || key.contains(matcher)) {
                    int score = matcher.length() + (key.equals(matcher) ? 100 : 0);
                    if (score > bestScore) {
                        bestScore = score;
                        best = stage;
                    }
                }
            }
        }
        return best;
    }

    private Map<String, Object> syntheticSummaryFromTools(List<QualityGateToolMetricDto> tools) {
        Map<String, Object> summary = new LinkedHashMap<>();
        Map<String, Object> sca = new LinkedHashMap<>();
        Map<String, Object> container = new LinkedHashMap<>();
        Map<String, Object> sast = new LinkedHashMap<>();
        Map<String, Object> dast = new LinkedHashMap<>();
        Map<String, Object> iac = new LinkedHashMap<>();
        int secrets = 0;

        for (QualityGateToolMetricDto t : tools) {
            switch (t.getId()) {
                case "trivy" -> {
                    sca.put("critical", t.getCritical());
                    sca.put("high", t.getHigh());
                    sca.put("medium", t.getMedium());
                    sca.put("low", t.getLow());
                }
                case "semgrep" -> {
                    sast.put("semgrep_high", t.getHigh());
                    sast.put("semgrep_medium", t.getMedium());
                }
                case "gitleaks" -> secrets = t.getTotal();
                case "grype" -> {
                    container.put("critical", t.getCritical());
                    container.put("high", t.getHigh());
                }
                case "checkov" -> iac.put("checkov_failed", t.getHigh());
                case "zap" -> {
                    dast.put("high", t.getHigh());
                    dast.put("medium", t.getMedium());
                    dast.put("low", t.getLow());
                }
                case "hadolint" -> sast.put("hadolint_errors", t.getHigh());
                default -> { }
            }
        }
        summary.put("sca", sca);
        summary.put("container", container);
        summary.put("sast", sast);
        summary.put("dast", dast);
        summary.put("iac", iac);
        summary.put("secrets", secrets);
        return summary;
    }

    private int countByToolMatchers(Map<String, Integer> byTool, String... matchers) {
        if (byTool == null || matchers.length == 0) return 0;
        int sum = 0;
        for (Map.Entry<String, Integer> e : byTool.entrySet()) {
            String hay = e.getKey().toLowerCase(Locale.ROOT);
            for (String m : matchers) {
                if (hay.contains(m.toLowerCase(Locale.ROOT))) {
                    sum += e.getValue() != null ? e.getValue() : 0;
                    break;
                }
            }
        }
        return sum;
    }

    private List<QualityGateStageDto> buildStages(
            List<Map<String, Object>> jobs,
            Map<String, Object> summary,
            Map<String, Object> storedGate,
            Map<String, Object> sonarFlat,
            boolean hasSummary
    ) {
        Map<String, Map<String, Object>> jobsByStage = indexJobs(jobs);
        List<QualityGateStageDto> stages = new ArrayList<>();
        boolean pipelineBlocked = false;

        for (String stageName : STAGE_ORDER) {
            Map<String, Object> job = findJob(jobsByStage, stageName);
            if (job == null && !isAlwaysShownStage(stageName, hasSummary, storedGate)) {
                continue;
            }
            QualityGateStageDto stage = evaluateStage(stageName, job, summary, sonarFlat, storedGate, pipelineBlocked);
            if (stage.isBlocking() && "FAIL".equals(stage.getStatus())) {
                pipelineBlocked = true;
            }
            if (pipelineBlocked && CASCADE_AFTER_BLOCK.contains(stageName)
                    && ("SKIPPED".equals(stage.getStatus()) || job == null)) {
                String jobSt = job != null ? stringVal(job.get("status")) : null;
                if (!gitlabSuccess(jobSt)) {
                    stage = stage.toBuilder()
                            .status("SKIPPED")
                            .statusLabel("Ignoré")
                            .message("(pas exécuté car gate précédent bloqué)")
                            .blocking(false)
                            .build();
                }
            }
            stages.add(stage);
        }

        if (stages.isEmpty() && storedGate != null) {
            String fallbackVerdict = stringVal(storedGate.get("verdict"));
            String fallbackRec = stringVal(storedGate.get("recommendation"));
            boolean meaningless = (fallbackVerdict == null || fallbackVerdict.isBlank() || "—".equals(fallbackVerdict))
                    && (fallbackRec == null || fallbackRec.isBlank() || "—".equals(fallbackRec));
            if (meaningless) {
                stages.add(QualityGateStageDto.builder()
                        .name("security-validation")
                        .toolLabel("Security Validation")
                        .status("FAIL").statusLabel("ÉCHEC")
                        .message("Le job security-validation n'a pas produit de résultat exploitable — les outils de scan ne se sont pas exécutés.")
                        .blocking(true)
                        .build());
            } else {
                stages.add(QualityGateStageDto.builder()
                        .name("security-validation")
                        .toolLabel("Security Validation")
                        .status(mapStageStatus(storedGate.get("verdict")))
                        .statusLabel(statusLabel(mapStageStatus(storedGate.get("verdict"))))
                        .message("Verdict CI : " + storedGate.get("recommendation"))
                        .blocking("FAIL".equals(mapStageStatus(storedGate.get("verdict"))))
                        .build());
            }
        }
        return stages;
    }

    private boolean isAlwaysShownStage(String stageName, boolean hasSummary, Map<String, Object> storedGate) {
        return "security-validation".equals(stageName) && (hasSummary || storedGate != null);
    }

    private Map<String, Map<String, Object>> indexJobs(List<Map<String, Object>> jobs) {
        Map<String, Map<String, Object>> jobsByStage = new LinkedHashMap<>();
        for (Map<String, Object> job : jobs) {
            String stage = stringVal(job.get("stage"));
            if (stage == null) {
                stage = stringVal(job.get("name"));
            }
            if (stage == null) {
                continue;
            }
            String key = stage.toLowerCase(Locale.ROOT);
            Map<String, Object> existing = jobsByStage.get(key);
            if (existing == null || jobStatusPriority(stringVal(job.get("status")))
                    > jobStatusPriority(stringVal(existing.get("status")))) {
                jobsByStage.put(key, job);
            }
        }
        return jobsByStage;
    }

    private Map<String, Object> findJob(Map<String, Map<String, Object>> jobsByStage, String stageName) {
        String canonical = stageName.toLowerCase(Locale.ROOT);
        for (String alias : stageAliases(canonical)) {
            Map<String, Object> job = jobsByStage.get(alias);
            if (job != null) {
                return job;
            }
        }
        for (Map<String, Object> job : jobsByStage.values()) {
            String jobStage = stringVal(job.get("stage"));
            String jobName = stringVal(job.get("name"));
            if (jobStage != null) {
                String js = jobStage.toLowerCase(Locale.ROOT);
                for (String alias : stageAliases(canonical)) {
                    if (js.equals(alias)) {
                        return job;
                    }
                }
            }
            if (jobName != null) {
                String jn = jobName.toLowerCase(Locale.ROOT);
                for (String alias : stageAliases(canonical)) {
                    if (jn.equals(alias) || jn.replace('_', '-').equals(alias)) {
                        return job;
                    }
                }
            }
        }
        return null;
    }

    /** Correspondance stricte — jamais de contains() (évite setup → sonarqube-setup). */
    private List<String> stageAliases(String canonical) {
        return switch (canonical) {
            case "setup" -> List.of("setup");
            case "clone" -> List.of("clone");
            case "code-analysis" -> List.of("code-analysis", "sonarqube-scan", "sonar");
            case "sonarqube-scan" -> List.of("sonarqube-scan", "code-analysis", "sonar");
            case "sonarqube-setup" -> List.of("sonarqube-setup");
            case "sca" -> List.of("sca", "sca-trivy");
            case "sca-trivy" -> List.of("sca-trivy", "sca");
            case "sast" -> List.of("sast", "semgrep");
            case "secrets" -> List.of("secrets", "gitleaks");
            case "secrets-iac" -> List.of("secrets-iac", "iac-secrets");
            case "iac" -> List.of("iac", "checkov");
            case "build" -> List.of("build", "build-image");
            case "build-image" -> List.of("build-image", "build");
            case "container-scan" -> List.of("container-scan", "container");
            case "push-image" -> List.of("push-image");
            case "deploy-k8s" -> List.of("deploy-k8s", "deploy");
            case "zap-scan" -> List.of("zap-scan", "zap", "dast");
            case "reporting" -> List.of("reporting", "aggregate-report", "aggregate");
            case "aggregate-report" -> List.of("aggregate-report", "reporting", "aggregate");
            case "import-defectdojo" -> List.of("import-defectdojo", "import_defectdojo");
            case "security-validation" -> List.of("security-validation", "security_validation");
            default -> List.of(canonical);
        };
    }

    private int jobStatusPriority(String status) {
        if (gitlabSuccess(status)) {
            return 5;
        }
        if (gitlabFailed(status)) {
            return 4;
        }
        if (gitlabManual(status)) {
            return 3;
        }
        if (gitlabSkipped(status)) {
            return 2;
        }
        if (gitlabPending(status)) {
            return 1;
        }
        return 0;
    }

    private QualityGateStageDto evaluateStage(
            String stageName,
            Map<String, Object> job,
            Map<String, Object> summary,
            Map<String, Object> sonarFlat,
            Map<String, Object> storedGate,
            boolean pipelineBlocked
    ) {
        String lower = stageName.toLowerCase(Locale.ROOT);
        String gitlabStatus = job != null ? normalizeGitlabJobStatus(stringVal(job.get("status"))) : null;
        String toolLabel = toolLabelForStage(stageName);
        Map<String, Object> stageMetrics = new LinkedHashMap<>();

        if (pipelineBlocked && CASCADE_AFTER_BLOCK.contains(lower)) {
            return baseStage(stageName, toolLabel, job)
                    .status("SKIPPED").statusLabel("Ignoré")
                    .message("(pas exécuté car gate précédent bloqué)")
                    .blocking(false).metrics(stageMetrics).build();
        }

        if (job != null && gitlabManual(gitlabStatus)) {
            return baseStage(stageName, toolLabel, job)
                    .status("SKIPPED").statusLabel("Manuel")
                    .message("En attente d'action manuelle dans GitLab")
                    .blocking(false).metrics(stageMetrics).build();
        }

        if (stageRequiresExecutedJob(lower)) {
            if (job == null || gitlabPending(gitlabStatus)
                    || (!gitlabSuccess(gitlabStatus) && !gitlabFailed(gitlabStatus))) {
                return skippedNotExecutedStage(stageName, toolLabel, job, gitlabStatus, stageMetrics);
            }
        }

        if (lower.contains("security-validation")) {
            if (job == null || gitlabPending(gitlabStatus)) {
                return skippedNotExecutedStage(stageName, toolLabel, job, gitlabStatus, stageMetrics);
            }
            if (gitlabFailed(gitlabStatus)) {
                return baseStage(stageName, toolLabel, job)
                        .status("FAIL").statusLabel("ÉCHEC")
                        .message("Job security-validation en échec sur GitLab")
                        .blocking(true).metrics(stageMetrics).build();
            }
            String ciRec = storedGate != null ? stringVal(storedGate.get("recommendation")) : null;
            String ciVerdict = storedGate != null ? stringVal(storedGate.get("verdict")) : null;
            boolean meaningless = (ciRec == null || ciRec.isBlank() || "—".equals(ciRec))
                    && (ciVerdict == null || ciVerdict.isBlank() || "—".equals(ciVerdict));
            if (meaningless) {
                return baseStage(stageName, toolLabel, job)
                        .status("FAIL").statusLabel("ÉCHEC")
                        .message("Le job security-validation n'a pas produit de résultat exploitable — les outils de scan ne se sont pas exécutés.")
                        .blocking(true).metrics(stageMetrics).build();
            }
            String verdictLabel = ciRec != null ? ciRec
                    : (ciVerdict != null ? ciVerdict : "—");
            String msg = "Job terminé avec succès — recommandation : " + verdictLabel;
            return baseStage(stageName, toolLabel, job)
                    .status("PASS").statusLabel("Réussi")
                    .message(msg)
                    .blocking(false).metrics(stageMetrics).build();
        }

        if (lower.contains("sonar") && !lower.contains("setup")) {
            int blocker = sonarViolationCount(sonarFlat, "blocker");
            int critical = sonarViolationCount(sonarFlat, "critical");
            int major = sonarViolationCount(sonarFlat, "major");
            int minor = sonarViolationCount(sonarFlat, "minor");
            stageMetrics.put("blocker", blocker);
            stageMetrics.put("critical", critical);
            stageMetrics.put("major", major);
            stageMetrics.put("minor", minor);
            Object qgStatus = sonarFlat.get("quality_gate_status");
            String qgStr = stringVal(qgStatus);
            boolean qgOk = isSonarQualityGatePassed(qgStr);
            int hotspots = intVal(sonarFlat.get("security_hotspots"));
            stageMetrics.put("hotspots", hotspots);
            String st;
            if (gitlabFailed(gitlabStatus)) {
                st = "FAIL";
            } else if ("ERROR".equalsIgnoreCase(qgStr)) {
                st = "FAIL";
            } else if (blocker > 0 || critical > 0) {
                st = qgOk ? "WARN" : "FAIL";
            } else if (major > 0) {
                st = "WARN";
            } else {
                st = "PASS";
            }
            if ("PASS".equals(st) && hotspots > 0) {
                st = "WARN";
            }
            String branchNote = sonarFlat.get("sonar_branch") != null
                    ? " (branche " + sonarFlat.get("sonar_branch") + ")" : "";
            String qgLabel = qgStatus != null ? " · QG Sonar: " + qgStr : "";
            String msg = String.format(
                    "SonarQube%s : %d blocker · %d critical · %d major · %d minor%s%s",
                    branchNote, blocker, critical, major, minor,
                    qgOk && (blocker + critical + major) > 0 ? " — QG OK mais violations ouvertes" : "",
                    qgLabel);
            return baseStage(stageName, toolLabel, job)
                    .status(st).statusLabel(statusLabel(st))
                    .message(msg).blocking("FAIL".equals(st)).metrics(stageMetrics).build();
        }

        if (lower.contains("sca") || lower.contains("trivy")) {
            Map<String, Object> sca = mapVal(summary, "sca");
            int crit = intVal(sca.get("critical"));
            int high = intVal(sca.get("high"));
            int med = intVal(sca.get("medium"));
            stageMetrics.put("critical", crit);
            stageMetrics.put("high", high);
            stageMetrics.put("medium", med);
            GateEval eval = evaluateSca(crit, high, med);
            String msg = String.format("%d critique(s), %d élevée(s), %d moyenne(s)%s",
                    crit, high, med, eval.blocking ? " (seuil critique > " + QualityGateThresholds.SCA_CRITICAL + " → bloquant)" : "");
            return baseStage(stageName, toolLabel, job)
                    .status(mergeGitlab(eval.status, gitlabStatus))
                    .statusLabel(statusLabel(mergeGitlab(eval.status, gitlabStatus)))
                    .message(msg).blocking(eval.blocking).metrics(stageMetrics).build();
        }

        if (lower.contains("sast") || lower.contains("semgrep")) {
            Map<String, Object> sast = mapVal(summary, "sast");
            int high = intVal(sast.get("semgrep_high"));
            int med = intVal(sast.get("semgrep_medium"));
            stageMetrics.put("high", high);
            stageMetrics.put("medium", med);
            GateEval eval = evaluateSemgrep(high, med);
            String msg = String.format("%d élevée(s), %d moyenne(s)%s",
                    high, med, eval.status.equals("WARN") ? " (high < seuil " + QualityGateThresholds.SEMGREP_HIGH + " mais alerte)" : "");
            return baseStage(stageName, toolLabel, job)
                    .status(mergeGitlab(eval.status, gitlabStatus))
                    .statusLabel(statusLabel(mergeGitlab(eval.status, gitlabStatus)))
                    .message(msg).blocking(eval.blocking).metrics(stageMetrics).build();
        }

        if (lower.contains("secret")) {
            int secrets = intVal(summary.get("secrets"));
            stageMetrics.put("secrets", secrets);
            String st = secrets > 0 ? "FAIL" : "PASS";
            String msg = secrets > 0 ? secrets + " secret(s) détecté(s) — bloquant" : "0 secret détecté";
            return baseStage(stageName, toolLabel, job)
                    .status(mergeGitlab(st, gitlabStatus, true))
                    .statusLabel(statusLabel(mergeGitlab(st, gitlabStatus, true)))
                    .message(msg).blocking(secrets > 0).metrics(stageMetrics).build();
        }

        if (lower.contains("container")) {
            Map<String, Object> c = mapVal(summary, "container");
            int crit = intVal(c.get("critical"));
            int high = intVal(c.get("high"));
            stageMetrics.put("critical", crit);
            stageMetrics.put("high", high);
            GateEval eval = evaluateContainer(crit, high);
            String msg = String.format("%d critique(s), %d élevée(s)%s",
                    crit, high, eval.blocking ? " (seuil critique > " + QualityGateThresholds.CONTAINER_CRITICAL + " → bloquant)" : "");
            return baseStage(stageName, toolLabel, job)
                    .status(mergeGitlab(eval.status, gitlabStatus))
                    .statusLabel(statusLabel(mergeGitlab(eval.status, gitlabStatus)))
                    .message(msg).blocking(eval.blocking).metrics(stageMetrics).build();
        }

        if (lower.contains("iac") || lower.contains("checkov")) {
            Map<String, Object> iac = mapVal(summary, "iac");
            int failed = intVal(iac.get("checkov_failed"));
            stageMetrics.put("failed", failed);
            GateEval eval = evaluateIac(failed);
            String msg = "Checkov : " + failed + " échec(s)" + (eval.blocking ? " (seuil dépassé)" : "");
            return baseStage(stageName, toolLabel, job)
                    .status(mergeGitlab(eval.status, gitlabStatus))
                    .statusLabel(statusLabel(mergeGitlab(eval.status, gitlabStatus)))
                    .message(msg).blocking(eval.blocking).metrics(stageMetrics).build();
        }

        if (lower.contains("zap") || lower.contains("dast")) {
            Map<String, Object> dast = mapVal(summary, "dast");
            int high = intVal(dast.get("high"));
            int med = intVal(dast.get("medium"));
            stageMetrics.put("high", high);
            stageMetrics.put("medium", med);
            GateEval eval = evaluateDast(high, med);
            String msg = String.format("DAST : %d élevée(s), %d moyenne(s)", high, med);
            return baseStage(stageName, toolLabel, job)
                    .status(mergeGitlab(eval.status, gitlabStatus))
                    .statusLabel(statusLabel(mergeGitlab(eval.status, gitlabStatus)))
                    .message(msg).blocking(eval.blocking).metrics(stageMetrics).build();
        }

        if (lower.contains("setup") || lower.contains("clone")) {
            String st = resolveGitlabStageStatus(job, gitlabStatus);
            return baseStage(stageName, toolLabel, job)
                    .status(st).statusLabel(statusLabel(st))
                    .message("PASS".equals(st) ? "Clone + détection des langages OK" : stageDefaultMessage(st, gitlabStatus, job))
                    .blocking("FAIL".equals(st)).metrics(stageMetrics).build();
        }

        if (lower.contains("build")) {
            String st = resolveGitlabStageStatus(job, gitlabStatus);
            return baseStage(stageName, toolLabel, job)
                    .status(st).statusLabel(statusLabel(st))
                    .message("PASS".equals(st) ? "Image Docker construite" : stageDefaultMessage(st, gitlabStatus, job))
                    .blocking(false).metrics(stageMetrics).build();
        }

        if (lower.contains("report") || lower.contains("aggregate") || lower.contains("import-defectdojo")) {
            String st = resolveGitlabStageStatus(job, gitlabStatus);
            return baseStage(stageName, toolLabel, job)
                    .status(st).statusLabel(statusLabel(st))
                    .message("PASS".equals(st) ? "Aggrégation des rapports OK" : stageDefaultMessage(st, gitlabStatus, job))
                    .blocking(false).metrics(stageMetrics).build();
        }

        String st = resolveGitlabStageStatus(job, gitlabStatus);
        return baseStage(stageName, toolLabel, job)
                .status(st).statusLabel(statusLabel(st))
                .message(stageDefaultMessage(st, gitlabStatus, job))
                .blocking("FAIL".equals(st) && isSecurityStage(lower))
                .metrics(stageMetrics).build();
    }

    private QualityGateStageDto.QualityGateStageDtoBuilder baseStage(String name, String toolLabel, Map<String, Object> job) {
        return QualityGateStageDto.builder()
                .name(name)
                .toolLabel(toolLabel)
                .details(job != null ? buildJobDetails(job) : Map.of());
    }

    private boolean isSecurityStage(String lower) {
        return lower.contains("sca") || lower.contains("sast") || lower.contains("secret")
                || lower.contains("container") || lower.contains("iac") || lower.contains("zap");
    }

    private String toolLabelForStage(String stageName) {
        if (stageName == null || stageName.isBlank()) {
            return "Stage";
        }
        String lower = stageName.toLowerCase(Locale.ROOT);
        return switch (lower) {
            case "sca", "sca-trivy" -> "SCA (Trivy FS)";
            case "sast" -> "SAST (Semgrep)";
            case "secrets", "secrets-iac" -> "Secrets (Gitleaks)";
            case "container-scan" -> "Container-Scan (Grype)";
            case "sonarqube-scan", "code-analysis" -> "Code-Analysis (SonarQube)";
            case "sonarqube-setup" -> "SonarQube Setup";
            case "iac" -> "IaC (Checkov)";
            case "zap-scan" -> "ZAP Scan (DAST)";
            case "security-validation" -> "Security-Validation";
            case "setup", "clone" -> "Setup";
            case "build", "build-image" -> "Build";
            case "push-image" -> "Push-Image";
            case "deploy-k8s" -> "Deploy-K8s";
            case "aggregate-report", "reporting" -> "Reporting";
            case "import-defectdojo" -> "import-defectdojo";
            default -> {
                if (lower.contains("semgrep")) yield "SAST (Semgrep)";
                if (lower.contains("gitleaks")) yield "Secrets (Gitleaks)";
                if (lower.contains("grype")) yield "Container-Scan (Grype)";
                if (lower.contains("checkov")) yield "IaC (Checkov)";
                if (lower.contains("trivy") && !lower.contains("container")) yield "SCA (Trivy FS)";
                if (lower.contains("sonar")) yield "Code-Analysis (SonarQube)";
                if (lower.contains("zap") || lower.contains("dast")) yield "ZAP Scan (DAST)";
                yield capitalizeStage(lower);
            }
        };
    }

    private String capitalizeStage(String s) {
        if (s == null || s.isBlank()) return s;
        return s.substring(0, 1).toUpperCase(Locale.ROOT) + s.substring(1).replace('-', ' ');
    }

    private record GateEval(String status, boolean blocking) {
    }

    private GateEval evaluateSca(int crit, int high, int med) {
        if (crit > QualityGateThresholds.SCA_CRITICAL) return new GateEval("FAIL", true);
        if (high > QualityGateThresholds.SCA_HIGH) return new GateEval("FAIL", true);
        if (med > QualityGateThresholds.SCA_MEDIUM_WARN) return new GateEval("WARN", false);
        if (crit > 0) return new GateEval("WARN", false);
        return new GateEval("PASS", false);
    }

    private GateEval evaluateSemgrep(int high, int med) {
        if (high > QualityGateThresholds.SEMGREP_HIGH) return new GateEval("FAIL", true);
        if (med > QualityGateThresholds.SEMGREP_MEDIUM) return new GateEval("WARN", false);
        if (high > 0) return new GateEval("WARN", false);
        return new GateEval("PASS", false);
    }

    private GateEval evaluateContainer(int crit, int high) {
        if (crit > QualityGateThresholds.CONTAINER_CRITICAL) return new GateEval("FAIL", true);
        if (high > QualityGateThresholds.CONTAINER_HIGH) return new GateEval("FAIL", true);
        if (crit > 0) return new GateEval("WARN", false);
        return new GateEval("PASS", false);
    }

    private GateEval evaluateIac(int failed) {
        if (failed > QualityGateThresholds.IAC_FAILED) return new GateEval("FAIL", true);
        if (failed > 0) return new GateEval("WARN", false);
        return new GateEval("PASS", false);
    }

    private GateEval evaluateDast(int high, int med) {
        if (high > QualityGateThresholds.DAST_HIGH) return new GateEval("FAIL", true);
        if (med > QualityGateThresholds.DAST_MEDIUM) return new GateEval("WARN", false);
        return new GateEval("PASS", false);
    }

    private String mergeGitlab(String gateStatus, String gitlabStatus) {
        return mergeGitlab(gateStatus, gitlabStatus, false);
    }

    /**
     * Priorité au statut GitLab réel. Ne pas marquer PASS si le job n'a pas tourné.
     */
    private String mergeGitlab(String gateStatus, String gitlabStatus, boolean respectGateOnGitlabSuccess) {
        if (gitlabFailed(gitlabStatus)) return "FAIL";
        if (gitlabSkipped(gitlabStatus)) return "SKIPPED";
        if (gitlabPending(gitlabStatus)) return "SKIPPED";
        if (gitlabSuccess(gitlabStatus)) {
            if (respectGateOnGitlabSuccess) {
                return gateStatus != null ? gateStatus : "PASS";
            }
            return gateStatus != null ? gateStatus : "PASS";
        }
        return gateStatus != null ? gateStatus : "SKIPPED";
    }

    private boolean gitlabSuccess(String gitlabStatus) {
        if (gitlabStatus == null) {
            return false;
        }
        String s = gitlabStatus.toLowerCase(Locale.ROOT);
        return "success".equals(s) || "passed".equals(s);
    }

    private boolean gitlabManual(String gitlabStatus) {
        return gitlabStatus != null && "manual".equalsIgnoreCase(gitlabStatus.trim());
    }

    private String normalizeGitlabJobStatus(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        return raw.trim().toLowerCase(Locale.ROOT);
    }

    private boolean gitlabPending(String gitlabStatus) {
        if (gitlabStatus == null || gitlabStatus.isBlank()) {
            return false;
        }
        String s = gitlabStatus.toLowerCase(Locale.ROOT);
        return "created".equals(s) || "pending".equals(s) || "running".equals(s)
                || "waiting_for_resource".equals(s) || "preparing".equals(s) || "scheduled".equals(s);
    }

    private String resolveGitlabStageStatus(Map<String, Object> job, String gitlabStatus) {
        if (job == null) {
            return "SKIPPED";
        }
        if (gitlabFailed(gitlabStatus)) {
            return "FAIL";
        }
        if (gitlabSkipped(gitlabStatus)) {
            return "SKIPPED";
        }
        if (gitlabPending(gitlabStatus)) {
            return "SKIPPED";
        }
        if (gitlabSuccess(gitlabStatus)) {
            return "PASS";
        }
        return "SKIPPED";
    }

    private boolean stageRequiresExecutedJob(String lowerStageName) {
        return lowerStageName.contains("sca") || lowerStageName.contains("trivy")
                || lowerStageName.contains("sast") || lowerStageName.contains("semgrep")
                || lowerStageName.contains("secret") || lowerStageName.contains("container")
                || lowerStageName.contains("iac") || lowerStageName.contains("checkov")
                || lowerStageName.contains("zap") || lowerStageName.contains("dast")
                || (lowerStageName.contains("sonar") && !lowerStageName.contains("setup"));
    }

    private QualityGateStageDto skippedNotExecutedStage(
            String stageName,
            String toolLabel,
            Map<String, Object> job,
            String gitlabStatus,
            Map<String, Object> stageMetrics
    ) {
        String msg = job == null
                ? "Stage non exécuté"
                : (gitlabPending(gitlabStatus) ? "Stage en cours d'exécution" : "Stage non exécuté");
        if (job != null && gitlabPending(gitlabStatus)) {
            return baseStage(stageName, toolLabel, job)
                    .status("RUNNING")
                    .statusLabel("En cours")
                    .message(msg)
                    .blocking(false)
                    .metrics(stageMetrics)
                    .build();
        }
        return baseStage(stageName, toolLabel, job)
                .status("SKIPPED")
                .statusLabel(job == null ? "Non exécuté" : "En attente")
                .message(msg)
                .blocking(false)
                .metrics(stageMetrics)
                .build();
    }

    private boolean isSonarQualityGatePassed(String qgStr) {
        if (qgStr == null || qgStr.isBlank()) {
            return false;
        }
        return switch (qgStr.trim().toUpperCase(Locale.ROOT)) {
            case "OK", "PASSED", "PASS" -> true;
            default -> false;
        };
    }

    private enum ImportDefectDojoJobState { MISSING, PENDING, FAILED, SUCCESS }

    private enum SonarScanJobState { MISSING, PENDING, FAILED, SUCCESS }

    private SonarScanJobState sonarScanJobState(PipelineExecution execution) {
        if (execution == null) {
            return SonarScanJobState.MISSING;
        }
        SonarScanJobState best = SonarScanJobState.MISSING;
        for (Map<String, Object> job : getJobsFromStagesJson(execution)) {
            String stage = stringVal(job.get("stage")).toLowerCase(Locale.ROOT);
            String name = stringVal(job.get("name")).toLowerCase(Locale.ROOT);
            if (stage.contains("setup") || name.contains("setup")) {
                continue;
            }
            boolean isSonarScan = name.contains("sonarqube-scan") || stage.contains("sonarqube-scan")
                    || name.contains("code-analysis") || stage.contains("code-analysis");
            if (!isSonarScan) {
                continue;
            }
            String st = normalizeGitlabJobStatus(stringVal(job.get("status")));
            best = maxSonarScanJobState(best, mapSonarScanJobState(st));
        }
        return best;
    }

    private SonarScanJobState mapSonarScanJobState(String status) {
        if (gitlabFailed(status)) {
            return SonarScanJobState.FAILED;
        }
        if (gitlabPending(status)) {
            return SonarScanJobState.PENDING;
        }
        if (gitlabSuccess(status)) {
            return SonarScanJobState.SUCCESS;
        }
        if (gitlabSkipped(status)) {
            return SonarScanJobState.FAILED;
        }
        return SonarScanJobState.MISSING;
    }

    private SonarScanJobState maxSonarScanJobState(SonarScanJobState a, SonarScanJobState b) {
        return sonarScanJobPriority(a) >= sonarScanJobPriority(b) ? a : b;
    }

    private int sonarScanJobPriority(SonarScanJobState state) {
        return switch (state) {
            case SUCCESS -> 4;
            case FAILED -> 3;
            case PENDING -> 2;
            case MISSING -> 1;
        };
    }

    private void clearSonarToolMetrics(List<QualityGateToolMetricDto> tools, List<QualityGateStageDto> stages) {
        if (tools != null) {
            for (QualityGateToolMetricDto tool : tools) {
                if ("sonarqube".equals(tool.getId())) {
                    tool.setCritical(0);
                    tool.setHigh(0);
                    tool.setMedium(0);
                    tool.setLow(0);
                    tool.setTotal(0);
                    tool.setStageStatus("FAIL");
                    tool.setStageLabel("SonarQube");
                }
            }
        }
        if (stages != null) {
            for (QualityGateStageDto stage : stages) {
                String name = stage.getName() != null ? stage.getName().toLowerCase(Locale.ROOT) : "";
                if (name.contains("sonar") && !name.contains("setup")) {
                    stage.setStatus("FAIL");
                    stage.setStatusLabel("ÉCHEC");
                    stage.setMessage(SONAR_JOB_FAILED_MSG);
                    stage.setBlocking(false);
                }
            }
        }
    }

    private ImportDefectDojoJobState importDefectDojoJobState(PipelineExecution execution) {
        if (execution == null) {
            return ImportDefectDojoJobState.MISSING;
        }
        for (Map<String, Object> job : getJobsFromStagesJson(execution)) {
            String hay = (stringVal(job.get("stage")) + " " + stringVal(job.get("name"))).toLowerCase(Locale.ROOT);
            if (!hay.contains("import-defectdojo") && !hay.contains("import_defectdojo")) {
                continue;
            }
            String st = stringVal(job.get("status"));
            if (gitlabFailed(st)) {
                return ImportDefectDojoJobState.FAILED;
            }
            if (gitlabPending(st)) {
                return ImportDefectDojoJobState.PENDING;
            }
            if (gitlabSuccess(st)) {
                return ImportDefectDojoJobState.SUCCESS;
            }
            return ImportDefectDojoJobState.PENDING;
        }
        return ImportDefectDojoJobState.MISSING;
    }

    private enum SecurityValidationJobState { MISSING, PENDING, FAILED, SUCCESS }

    private SecurityValidationJobState securityValidationJobState(PipelineExecution execution) {
        if (execution == null) {
            return SecurityValidationJobState.MISSING;
        }
        for (Map<String, Object> job : getJobsFromStagesJson(execution)) {
            String hay = (stringVal(job.get("stage")) + " " + stringVal(job.get("name"))).toLowerCase(Locale.ROOT);
            if (!hay.contains("security-validation") && !hay.contains("security_validation")) {
                continue;
            }
            String st = stringVal(job.get("status"));
            if (gitlabFailed(st)) {
                return SecurityValidationJobState.FAILED;
            }
            if (gitlabPending(st)) {
                return SecurityValidationJobState.PENDING;
            }
            if (gitlabSuccess(st)) {
                if (!hasSecurityValidationProducedMeaningfulResult(execution)) {
                    return SecurityValidationJobState.FAILED;
                }
                return SecurityValidationJobState.SUCCESS;
            }
            return SecurityValidationJobState.PENDING;
        }
        return SecurityValidationJobState.MISSING;
    }

    private boolean hasSecurityValidationProducedMeaningfulResult(PipelineExecution execution) {
        Map<String, Object> storedGate = execution.getQualityGateJson();
        if (storedGate == null || storedGate.isEmpty()) {
            return false;
        }
        String verdict = stringVal(storedGate.get("verdict"));
        String recommendation = stringVal(storedGate.get("recommendation"));
        if ((verdict == null || verdict.isBlank() || "—".equals(verdict))
                && (recommendation == null || recommendation.isBlank() || "—".equals(recommendation))) {
            return false;
        }
        return true;
    }

    /**
     * Le hard gate secrets n'est évaluable que si le job Gitleaks/secrets a réussi sur GitLab.
     * Des secrets détectés ne sont pas une « erreur » de job.
     */
    private boolean isSecretsJobEvaluable(PipelineExecution execution) {
        GitlabJobState state = gitlabJobStateForStages(execution, "secrets", "secrets-iac", "gitleaks");
        return state == GitlabJobState.SUCCESS;
    }

    private static final Map<String, String[]> TOOL_GITLAB_STAGES = Map.ofEntries(
            Map.entry("trivy", new String[]{"sca", "sca-trivy", "trivy"}),
            Map.entry("semgrep", new String[]{"sast", "semgrep"}),
            Map.entry("gitleaks", new String[]{"secrets", "secrets-iac", "gitleaks"}),
            Map.entry("grype", new String[]{"container-scan", "container", "grype"}),
            Map.entry("checkov", new String[]{"iac", "checkov"}),
            Map.entry("zap", new String[]{"zap-scan", "zap", "dast"}),
            Map.entry("hadolint", new String[]{"hadolint"}),
            Map.entry("sonarqube", new String[]{"sonarqube-scan", "code-analysis", "sonar"})
    );

    private void applyPipelineJobEvaluability(QualityGateResultDto dto, PipelineExecution execution) {
        if (dto == null) {
            return;
        }
        Map<String, Object> sonarFlat = resolveSonarFlatForPresentation(
                dto,
                execution != null ? execution.getQualityGateJson() : null,
                resolveEffectiveSummary(execution, execution != null ? execution.getQualityGateJson() : null));
        refreshSonarToolMetric(dto, sonarFlat);
        refreshCombinedCriticalHardGate(dto);
        if (dto.getToolMetrics() != null && !dto.getToolMetrics().isEmpty()) {
            applyToolEvaluability(dto.getToolMetrics(), execution);
        }
        annotateRecommendationReliability(dto, execution);
    }

    private void applyToolEvaluability(List<QualityGateToolMetricDto> tools, PipelineExecution execution) {
        if (tools == null || tools.isEmpty()) {
            return;
        }
        List<QualityGateToolMetricDto> patched = new ArrayList<>();
        for (QualityGateToolMetricDto tool : tools) {
            String[] stageKeys = TOOL_GITLAB_STAGES.get(tool.getId());
            if (stageKeys == null || execution == null) {
                patched.add(tool.toBuilder().evaluable(true).build());
                continue;
            }
            GitlabJobState state = gitlabJobStateForStages(execution, stageKeys);
            QualityGateToolMetricDto.QualityGateToolMetricDtoBuilder b = tool.toBuilder();
            if (state == GitlabJobState.FAILED) {
                boolean hasData = tool.getTotal() > 0;
                b.evaluable(hasData);
                if (!hasData) {
                    b.critical(0).high(0).medium(0).low(0).total(0);
                }
                b.stageStatus("FAIL");
            } else if (state == GitlabJobState.SUCCESS) {
                // Job GitLab OK : findings (ex. secrets) ≠ erreur de job.
                b.evaluable(true).stageStatus("PASS");
            } else {
                b.evaluable(true);
            }
            patched.add(b.build());
        }
        tools.clear();
        tools.addAll(patched);
    }

    private void annotateRecommendationReliability(QualityGateResultDto dto, PipelineExecution execution) {
        if (dto == null || "SECURITY_VALIDATION_FAILED".equals(dto.getVerdictSource())) {
            return;
        }
        List<String> unreliableJobs = collectUnreliableScanJobs(execution);
        boolean reliable = unreliableJobs.isEmpty();
        dto.setRecommendationReliable(reliable);
        dto.setFailedScanJobs(unreliableJobs.isEmpty() ? List.of() : unreliableJobs);
        if (!reliable) {
            dto.setReliabilityMessage(buildReliabilityMessage(unreliableJobs));
            if (dto.getMetrics() == null) {
                dto.setMetrics(new LinkedHashMap<>());
            }
            dto.getMetrics().put("recommendationReliable", false);
            dto.getMetrics().put("failedScanJobs", unreliableJobs);
        } else {
            dto.setReliabilityMessage(null);
            if (dto.getMetrics() != null) {
                dto.getMetrics().put("recommendationReliable", true);
            }
        }
    }

    /** Jobs scan GitLab en échec ou non exécutés — Sonar/DefectDojo exclus (snapshot BDD). */
    private List<String> collectUnreliableScanJobs(PipelineExecution execution) {
        if (execution == null) {
            return List.of();
        }
        LinkedHashSet<String> labels = new LinkedHashSet<>();
        for (Map.Entry<String, String[]> entry : TOOL_GITLAB_STAGES.entrySet()) {
            if ("sonarqube".equals(entry.getKey())) {
                continue;
            }
            GitlabJobState state = gitlabJobStateForStages(execution, entry.getValue());
            if (state == GitlabJobState.SUCCESS) {
                continue;
            }
            String label = toolLabelForMetricId(entry.getKey());
            if (state == GitlabJobState.FAILED) {
                labels.add(label);
            } else if (state == GitlabJobState.MISSING || state == GitlabJobState.SKIPPED
                    || state == GitlabJobState.PENDING || state == GitlabJobState.MANUAL) {
                labels.add(label + " (non exécuté)");
            }
        }
        return new ArrayList<>(labels);
    }

    private String toolLabelForMetricId(String toolId) {
        return switch (toolId) {
            case "trivy" -> "Trivy FS";
            case "semgrep" -> "Semgrep";
            case "gitleaks" -> "Secrets (Gitleaks)";
            case "grype" -> "Grype";
            case "checkov" -> "Checkov";
            case "zap" -> "OWASP ZAP";
            case "hadolint" -> "Hadolint";
            default -> toolId;
        };
    }

    private String buildReliabilityMessage(List<String> unreliableJobs) {
        if (unreliableJobs == null || unreliableJobs.isEmpty()) {
            return null;
        }
        return "Recommandation peu fiable — "
                + String.join(", ", unreliableJobs)
                + " : vérifiez le job dans le pipeline GitLab, corrigez l'erreur puis relancez le job security-validation.";
    }

    private enum GitlabJobState { MISSING, PENDING, MANUAL, FAILED, SUCCESS, SKIPPED }

    private GitlabJobState gitlabJobStateForStages(PipelineExecution execution, String... canonicalStages) {
        if (execution == null) {
            return GitlabJobState.MISSING;
        }
        List<Map<String, Object>> jobs = getJobsFromStagesJson(execution);
        if (jobs.isEmpty()) {
            return GitlabJobState.MISSING;
        }
        Map<String, Map<String, Object>> byStage = indexJobs(jobs);
        GitlabJobState best = GitlabJobState.MISSING;
        for (String canonical : canonicalStages) {
            Map<String, Object> job = findJob(byStage, canonical);
            if (job == null) {
                continue;
            }
            GitlabJobState st = mapGitlabJobState(normalizeGitlabJobStatus(stringVal(job.get("status"))));
            best = maxJobState(best, st);
        }
        return best;
    }

    private GitlabJobState mapGitlabJobState(String status) {
        if (status == null || status.isBlank()) {
            return GitlabJobState.PENDING;
        }
        if (gitlabSuccess(status)) {
            return GitlabJobState.SUCCESS;
        }
        if (gitlabFailed(status)) {
            return GitlabJobState.FAILED;
        }
        if (gitlabManual(status)) {
            return GitlabJobState.MANUAL;
        }
        if (gitlabSkipped(status)) {
            return GitlabJobState.SKIPPED;
        }
        if (gitlabPending(status)) {
            return GitlabJobState.PENDING;
        }
        return GitlabJobState.PENDING;
    }

    private GitlabJobState maxJobState(GitlabJobState a, GitlabJobState b) {
        return jobStatePriority(a) >= jobStatePriority(b) ? a : b;
    }

    private int jobStatePriority(GitlabJobState state) {
        return switch (state) {
            case SUCCESS -> 5;
            case FAILED -> 4;
            case MANUAL -> 3;
            case SKIPPED -> 2;
            case PENDING -> 1;
            case MISSING -> 0;
        };
    }

    /**
     * DefectDojo est « disponible » pour les hard gates seulement si configuré, sans erreur API,
     * et le job import-defectdojo a réussi (ou pipeline terminé sans job import explicite).
     */
    private boolean isDefectDojoAvailableForQualityGate(
            DefectDojoDashboard2Response dd,
            PipelineExecution execution
    ) {
        if (dd == null || !dd.isConfigured()) {
            return false;
        }
        if (dd.getMessage() != null && !dd.getMessage().isBlank()) {
            return false;
        }
        ImportDefectDojoJobState importState = importDefectDojoJobState(execution);
        if (importState == ImportDefectDojoJobState.FAILED) {
            return false;
        }
        if (importState == ImportDefectDojoJobState.PENDING) {
            return false;
        }
        if (importState == ImportDefectDojoJobState.SUCCESS) {
            return true;
        }
        if (execution != null && execution.getStatus() != null && !execution.getStatus().isFinished()) {
            return false;
        }
        return true;
    }

    private String overrideByGitlab(String gateStatus, String gitlabStatus) {
        if (gitlabFailed(gitlabStatus)) return "FAIL";
        if (gitlabSkipped(gitlabStatus)) return "SKIPPED";
        return gateStatus;
    }

    private boolean gitlabFailed(String gitlabStatus) {
        return gitlabStatus != null && "failed".equalsIgnoreCase(gitlabStatus.trim());
    }

    private boolean gitlabSkipped(String gitlabStatus) {
        if (gitlabStatus == null) {
            return false;
        }
        String s = gitlabStatus.toLowerCase(Locale.ROOT);
        return "skipped".equals(s) || "canceled".equals(s) || "cancelled".equals(s);
    }

    private String stageDefaultMessage(String st, String gitlabStatus, Map<String, Object> job) {
        if ("SKIPPED".equals(st)) {
            if (job == null) {
                return "Stage non exécuté";
            }
            if (gitlabPending(gitlabStatus)) {
                return "En cours d'exécution";
            }
            return "Étape ignorée ou non exécutée";
        }
        if ("FAIL".equals(st)) return "Job échoué dans GitLab";
        return "OK";
    }

    private String stageDefaultMessage(String st, String gitlabStatus) {
        return stageDefaultMessage(st, gitlabStatus, null);
    }

    private String statusLabel(String status) {
        return switch (status) {
            case "PASS" -> "Réussi";
            case "WARN" -> "Warning";
            case "FAIL" -> "ÉCHEC";
            case "RUNNING" -> "En cours";
            case "SKIPPED" -> "Ignoré";
            default -> status;
        };
    }

    private Map<String, Object> buildJobDetails(Map<String, Object> job) {
        Map<String, Object> details = new LinkedHashMap<>();
        if (job.get("id") != null) details.put("jobId", job.get("id"));
        if (job.get("name") != null) details.put("jobName", job.get("name"));
        Object webUrl = job.get("web_url");
        if (webUrl != null) details.put("webUrl", webUrl);
        return details;
    }

    private Map<String, Object> buildMetrics(
            Map<String, Integer> bySeverity,
            Map<String, Object> summary,
            List<QualityGateStageDto> stages,
            Map<String, Object> sonarFlat,
            DefectDojoDashboard2Response dd,
            List<SoftwareQualityDimensionDto> softwareQuality,
            Map<String, Integer> softwareQualitySeverity,
            int resolvedNcloc
    ) {
        Map<String, Object> metrics = new LinkedHashMap<>();
        int severitySum = bySeverity.values().stream().mapToInt(Integer::intValue).sum();
        int totalOpen = severitySum > 0
                ? severitySum
                : (dd != null && dd.getTotalOpen() > 0 ? dd.getTotalOpen() : 0);
        metrics.put("totalVulnerabilities", totalOpen);
        metrics.put("bySeverity", bySeverity);
        if (resolvedNcloc > 0) {
            metrics.put("ncloc", resolvedNcloc);
        }

        long blockingFails = stages.stream()
                .filter(s -> "FAIL".equals(s.getStatus()) && s.isBlocking())
                .count();
        long warnStages = stages.stream().filter(s -> "WARN".equals(s.getStatus())).count();
        metrics.put("failedStages", blockingFails);
        metrics.put("blockingStages", blockingFails);
        metrics.put("warningStages", warnStages);
        metrics.put("secrets", intVal(summary.get("secrets")));

        Map<String, Object> sonarMetrics = new LinkedHashMap<>();
        if (!sonarFlat.isEmpty()) {
            sonarMetrics.put("bugs", intVal(sonarFlat.get("bugs")));
            sonarMetrics.put("vulnerabilities", intVal(sonarFlat.get("vulnerabilities")));
            sonarMetrics.put("codeSmells", intVal(sonarFlat.get("code_smells")));
            sonarMetrics.put("openIssues", intVal(sonarFlat.get("open_issues")));
            sonarMetrics.put("coverage", doubleVal(sonarFlat.get("coverage")));
            sonarMetrics.put("duplications", doubleVal(sonarFlat.get("duplicated_lines_density")));
            sonarMetrics.put("hotspots", intVal(sonarFlat.get("security_hotspots")));
        }
        int sonarNcloc = resolvedNcloc > 0 ? resolvedNcloc : intVal(sonarFlat.get("ncloc"));
        if (sonarNcloc > 0) {
            sonarMetrics.put("ncloc", sonarNcloc);
        }

        if (!sonarMetrics.isEmpty()) {
            Map<String, Integer> sonarBySev = sonarViolationBySeverity(sonarFlat);
            if (sonarBySev.values().stream().anyMatch(v -> v > 0)) {
                sonarMetrics.put("bySeverity", sonarBySev);
            }

            sonarMetrics.put("openSecurity", intVal(sonarFlat.get("software_quality_security_issues")));
            sonarMetrics.put("openReliability", intVal(sonarFlat.get("software_quality_reliability_issues")));
            sonarMetrics.put("openMaintainability", intVal(sonarFlat.get("software_quality_maintainability_issues")));

            String secRating = SecurityScoringService.ratingToLetter(firstNonNull(
                    sonarFlat.get("software_quality_security_rating_letter"),
                    sonarFlat.get("software_quality_security_rating"),
                    sonarFlat.get("security_rating")));
            String relRating = SecurityScoringService.ratingToLetter(firstNonNull(
                    sonarFlat.get("software_quality_reliability_rating_letter"),
                    sonarFlat.get("software_quality_reliability_rating"),
                    sonarFlat.get("reliability_rating")));
            String maintRating = SecurityScoringService.ratingToLetter(firstNonNull(
                    sonarFlat.get("software_quality_maintainability_rating_letter"),
                    sonarFlat.get("software_quality_maintainability_rating"),
                    sonarFlat.get("sqale_rating")));
            if (secRating != null) sonarMetrics.put("securityRating", secRating);
            if (relRating != null) sonarMetrics.put("reliabilityRating", relRating);
            if (maintRating != null) sonarMetrics.put("maintainabilityRating", maintRating);

            Object qg = sonarFlat.get("quality_gate");
            if (qg instanceof Map<?, ?> qgm) {
                sonarMetrics.put("rating", qgm.get("rating"));
                sonarMetrics.put("status", qgm.get("status"));
                sonarMetrics.put("conditions", qgm.get("conditions"));
            }
            if (sonarFlat.get("quality_gate_status") != null) {
                sonarMetrics.put("status", sonarFlat.get("quality_gate_status"));
            }
            if (sonarFlat.get("quality_gate_failed_conditions") != null) {
                sonarMetrics.put("failedConditions", sonarFlat.get("quality_gate_failed_conditions"));
            }
            if (sonarFlat.get("sonar_branch") != null) {
                sonarMetrics.put("branch", sonarFlat.get("sonar_branch"));
            }
            if (!softwareQuality.isEmpty()) {
                sonarMetrics.put("softwareQuality", softwareQuality);
            }
            if (!softwareQualitySeverity.isEmpty()) {
                sonarMetrics.put("softwareQualitySeverity", softwareQualitySeverity);
            }
            metrics.put("sonarQube", sonarMetrics);
        }
        return metrics;
    }

    private SonarAvailabilityDto buildSonarAvailability(
            Map<String, Object> sonar,
            AppService app,
            boolean liveAvailable
    ) {
        String projectKey = sonar.get("sonar_project_key") != null
                ? stringVal(sonar.get("sonar_project_key"))
                : SonarProjectKeyUtil.deriveSonarProjectKey(app.getGitRepositoryUrl());
        String requested = stringVal(sonar.get("requested_branch"));
        String resolved = stringVal(sonar.get("branch"));
        String message = stringVal(sonar.get("branch_fallback_message"));
        if (!liveAvailable && isBlankStr(message)) {
            message = "SonarQube indisponible — impossible de valider les hard gates Blocker et Quality Gate.";
        }
        String host = stringVal(sonar.get("sonar_host_url"));
        if (!isBlankStr(host)) {
            host = host.replaceAll("/+$", "");
        }
        String dashboardUrl = null;
        if (!isBlankStr(projectKey) && !isBlankStr(resolved) && !isBlankStr(host)) {
            dashboardUrl = host + "/dashboard?id=" + projectKey + "&branch=" + resolved;
        }
        return SonarAvailabilityDto.builder()
                .available(liveAvailable)
                .projectKey(isBlankStr(projectKey) ? null : projectKey)
                .requestedBranch(nullIfBlank(requested))
                .resolvedBranch(nullIfBlank(resolved))
                .message(nullIfBlank(message))
                .dashboardUrl(dashboardUrl)
                .build();
    }

    private List<SoftwareQualityDimensionDto> buildSoftwareQualityDimensions(
            Map<String, Object> sonarFlat,
            boolean sonarAvailable
    ) {
        if (!sonarAvailable || sonarFlat == null || sonarFlat.isEmpty()) {
            return List.of();
        }
        List<SoftwareQualityDimensionDto> dims = new ArrayList<>();
        dims.add(buildSoftwareQualityDimension(
                "SECURITY",
                "software_quality_security_issues",
                "software_quality_security_rating",
                "software_quality_security_high_issues",
                "software_quality_security_medium_issues",
                "software_quality_security_low_issues",
                sonarFlat));
        dims.add(buildSoftwareQualityDimension(
                "RELIABILITY",
                "software_quality_reliability_issues",
                "software_quality_reliability_rating",
                "software_quality_reliability_high_issues",
                "software_quality_reliability_medium_issues",
                "software_quality_reliability_low_issues",
                sonarFlat));
        dims.add(buildSoftwareQualityDimension(
                "MAINTAINABILITY",
                "software_quality_maintainability_issues",
                "software_quality_maintainability_rating",
                "software_quality_maintainability_high_issues",
                "software_quality_maintainability_medium_issues",
                "software_quality_maintainability_low_issues",
                sonarFlat));
        return dims;
    }

    private SoftwareQualityDimensionDto buildSoftwareQualityDimension(
            String dimension,
            String issuesKey,
            String ratingKey,
            String highKey,
            String mediumKey,
            String lowKey,
            Map<String, Object> sonarFlat
    ) {
        Object ratingRaw = sonarFlat.get(ratingKey);
        if (ratingRaw == null || intVal(ratingRaw) == 0) {
            ratingRaw = switch (dimension) {
                case "SECURITY" -> firstNonNull(
                        sonarFlat.get("security_rating"),
                        sonarFlat.get("software_quality_security_rating"));
                case "RELIABILITY" -> firstNonNull(
                        sonarFlat.get("reliability_rating"),
                        sonarFlat.get("software_quality_reliability_rating"));
                default -> firstNonNull(
                        sonarFlat.get("sqale_rating"),
                        sonarFlat.get("software_quality_maintainability_rating"));
            };
        }
        String rating = SecurityScoringService.ratingToLetter(ratingRaw);
        int ratingValue = SecurityScoringService.ratingNumeric(ratingRaw);
        int issues = intVal(sonarFlat.get(issuesKey));

        Map<String, Integer> bySeverity = null;
        int high = intVal(sonarFlat.get(highKey));
        int medium = intVal(sonarFlat.get(mediumKey));
        int low = intVal(sonarFlat.get(lowKey));
        if (high > 0 || medium > 0 || low > 0) {
            bySeverity = new LinkedHashMap<>();
            bySeverity.put("high", high);
            bySeverity.put("medium", medium);
            bySeverity.put("low", low);
        }

        return SoftwareQualityDimensionDto.builder()
                .dimension(dimension)
                .issues(issues)
                .rating(rating)
                .ratingValue(ratingValue)
                .bySeverity(bySeverity)
                .build();
    }

    private Map<String, Integer> buildSoftwareQualitySeverity(Map<String, Object> sonarFlat) {
        Object nested = sonarFlat.get("software_quality_severity");
        if (nested instanceof Map<?, ?> m) {
            Map<String, Integer> out = new LinkedHashMap<>();
            m.forEach((k, v) -> out.put(String.valueOf(k), intVal(v)));
            if (out.values().stream().anyMatch(v -> v > 0)) {
                return out;
            }
        }
        int high = intVal(sonarFlat.get("software_quality_high_severity_issues"));
        int medium = intVal(sonarFlat.get("software_quality_medium_severity_issues"));
        int low = intVal(sonarFlat.get("software_quality_low_severity_issues"));
        if (high == 0 && medium == 0 && low == 0) {
            return Map.of();
        }
        Map<String, Integer> out = new LinkedHashMap<>();
        out.put("high", high);
        out.put("medium", medium);
        out.put("low", low);
        return out;
    }

    private SecurityScoreInput buildSecurityScoreInput(
            Map<String, Integer> bySeverity,
            Map<String, Object> summary,
            List<QualityGateStageDto> stages,
            Map<String, Object> sonarFlat,
            Map<String, Object> sonar,
            Map<String, Object> storedGate,
            boolean defectDojoAvailable,
            boolean sonarLiveAvailable,
            int sonarBlockers,
            int resolvedNcloc
    ) {
        Map<String, Object> container = mapVal(summary, "container");
        int containerCritical = intVal(container.get("critical"));
        if (containerCritical == 0 && storedGate != null) {
            containerCritical = intVal(storedGate.get("containerCritical"));
        }

        int containerThreshold = thresholdFromSummaryOrDefault(
                summary, "containerCritical", QualityGateThresholds.CONTAINER_CRITICAL);
        int scaCriticalThreshold = thresholdFromSummaryOrDefault(
                summary, "scaCritical", QualityGateThresholds.SCA_CRITICAL);

        String securityRating = SecurityScoringService.ratingToLetter(
                firstNonNull(sonarFlat.get("software_quality_security_rating"), sonarFlat.get("security_rating")));
        String reliabilityRating = SecurityScoringService.ratingToLetter(
                firstNonNull(sonarFlat.get("software_quality_reliability_rating"), sonarFlat.get("reliability_rating")));
        String maintainabilityRating = SecurityScoringService.ratingToLetter(
                firstNonNull(sonarFlat.get("software_quality_maintainability_rating"), sonarFlat.get("sqale_rating")));

        return SecurityScoreInput.builder()
                .ddBySeverity(bySeverity)
                .secrets(intVal(summary.get("secrets")))
                .containerCritical(containerCritical)
                .containerCriticalThreshold(containerThreshold)
                .scaCriticalThreshold(scaCriticalThreshold)
                .sonarQgStatus(stringVal(sonarFlat.get("quality_gate_status")))
                .securityRating(securityRating)
                .reliabilityRating(reliabilityRating)
                .maintainabilityRating(maintainabilityRating)
                .coverage(doubleVal(sonarFlat.get("coverage")))
                .coverageKnown(sonarFlat.containsKey("coverage")
                        && sonarFlat.get("coverage") != null
                        && !isBlankStr(stringVal(sonarFlat.get("coverage"))))
                .securityHotspots(intVal(sonarFlat.get("security_hotspots")))
                .stages(stages)
                .sonarAvailable(sonarLiveAvailable)
                .defectDojoAvailable(defectDojoAvailable)
                .sonarBlockers(sonarBlockers)
                .ncloc(resolvedNcloc > 0 ? resolvedNcloc : intVal(sonarFlat.get("ncloc")))
                .build();
    }

    /**
     * Résout ncloc pour le score densité : Sonar live → summary.json → quality_gate_json pipeline.
     */
    @SuppressWarnings("unchecked")
    private NclocResolution resolveNcloc(
            Map<String, Object> sonarFlat,
            Map<String, Object> summary,
            Map<String, Object> storedGate
    ) {
        int fromSonar = intVal(sonarFlat != null ? sonarFlat.get("ncloc") : null);
        if (fromSonar > 0) {
            return new NclocResolution(fromSonar, "SONAR_LIVE");
        }

        int fromSummary = extractNclocFromMap(summary);
        if (fromSummary > 0) {
            return new NclocResolution(fromSummary, "SUMMARY");
        }

        if (storedGate != null) {
            int fromGate = intVal(storedGate.get("sonarNcloc"));
            if (fromGate > 0) {
                return new NclocResolution(fromGate, "PIPELINE_GATE");
            }
            Object nestedSummary = storedGate.get("summary");
            if (nestedSummary instanceof Map<?, ?> sm) {
                fromSummary = extractNclocFromMap((Map<String, Object>) sm);
                if (fromSummary > 0) {
                    return new NclocResolution(fromSummary, "SUMMARY");
                }
            }
        }

        return new NclocResolution(0, "UNKNOWN");
    }

    @SuppressWarnings("unchecked")
    private int extractNclocFromMap(Map<String, Object> map) {
        if (map == null || map.isEmpty()) {
            return 0;
        }
        int direct = intVal(map.get("ncloc"));
        if (direct > 0) {
            return direct;
        }
        Object sonar = map.get("sonar");
        if (sonar instanceof Map<?, ?> sonarMap) {
            int nested = intVal(sonarMap.get("ncloc"));
            if (nested > 0) {
                return nested;
            }
        }
        return 0;
    }

    private int thresholdFromSummaryOrDefault(
            Map<String, Object> summary,
            String key,
            int defaultValue
    ) {
        Object thresholds = summary.get("thresholds");
        if (thresholds instanceof Map<?, ?> tm) {
            Object v = tm.get(key);
            if (v != null) return intVal(v);
        }
        return defaultValue;
    }

    private Object firstNonNull(Object... values) {
        if (values == null) return null;
        for (Object v : values) {
            if (v != null) return v;
        }
        return null;
    }

    private String normalizeCiVerdict(String raw) {
        if (raw == null || raw.isBlank() || "UNKNOWN".equals(raw)) {
            return null;
        }
        return switch (raw) {
            case "RECOMMANDE", "RECOMMENDED" -> "RECOMMENDED";
            case "DEPLOY_WITH_WARNINGS", "WITH_WARNINGS" -> "WITH_WARNINGS";
            case "NON_RECOMMANDE", "NOT_RECOMMENDED" -> "NOT_RECOMMENDED";
            default -> raw;
        };
    }

    private VerdictResolution resolveDeterministicVerdict(
            SecurityScoringService.HardGateEvaluation hardGates,
            SecurityScoreDto postureScore
    ) {
        if (hardGates != null && !hardGates.violations().isEmpty()) {
            return new VerdictResolution("NOT_RECOMMENDED", "HARD_GATES");
        }
        if (hardGates != null && !hardGates.indeterminateSources().isEmpty()) {
            return new VerdictResolution("INDETERMINE", "HARD_GATES");
        }
        if (postureScore != null && postureScore.getDerivedVerdict() != null) {
            return new VerdictResolution(postureScore.getDerivedVerdict(), "POSTURE");
        }
        return new VerdictResolution("WITH_WARNINGS", "POSTURE");
    }

    private String buildIncompleteRecommendationMessage(List<String> indeterminateSources) {
        if (indeterminateSources == null || indeterminateSources.isEmpty()) {
            return null;
        }
        return "Recommandation incomplète — "
                + String.join(", ", indeterminateSources)
                + " indisponible(s), métriques non prises en compte. "
                + "Vérifiez les erreurs dans le pipeline GitLab, corrigez les jobs en échec "
                + "puis relancez les stages concernés pour obtenir une recommandation complète.";
    }

    @SuppressWarnings("unchecked")
    private boolean isSonarLiveAvailable(Map<String, Object> sonar) {
        if (sonar == null || sonar.isEmpty()) {
            return false;
        }
        if (!Boolean.TRUE.equals(sonar.get("sonar_available"))) {
            return false;
        }
        Object branchResolution = sonar.get("branch_resolution");
        if (branchResolution instanceof Map<?, ?> br) {
            Object reachable = br.get("sonarReachable");
            if (reachable instanceof Boolean b && !b) {
                return false;
            }
        } else if (branchResolution instanceof com.backend.devsecopsplatform_backend.service.SonarBranchResolution br) {
            if (!br.isSonarReachable()) {
                return false;
            }
        }
        return true;
    }

    /**
     * Si Sonar live échoue (API branches, réseau backend), retombe sur les métriques
     * remontées par le job CI (qualityGateJson / summary.json).
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> mergePipelineSonarIfNeeded(
            Map<String, Object> sonar,
            Map<String, Object> storedGate,
            Map<String, Object> summary,
            SonarScanJobState sonarJobState
    ) {
        if (sonarJobState == SonarScanJobState.FAILED) {
            Map<String, Object> unavailable = new LinkedHashMap<>();
            unavailable.put("sonar_available", false);
            unavailable.put("sonar_job_failed", true);
            unavailable.put("branch_fallback_message", SONAR_JOB_FAILED_MSG);
            return unavailable;
        }
        if (isSonarLiveAvailable(sonar)) {
            Map<String, Object> pipeline = buildSonarFromPipelineArtifacts(storedGate, summary);
            if (!pipeline.isEmpty()) {
                sonar = mergeLiveSonarWithPipelineSq(sonar, pipeline);
            }
            return sonar;
        }
        Map<String, Object> pipeline = buildSonarFromPipelineArtifacts(storedGate, summary);
        if (!pipeline.isEmpty()) {
            Map<String, Object> merged = new LinkedHashMap<>();
            if (sonar != null) {
                merged.putAll(sonar);
            }

            Object existingMetrics = merged.get("metrics");
            Object pipelineMetrics = pipeline.get("metrics");
            if (existingMetrics instanceof Map<?, ?> em && pipelineMetrics instanceof Map<?, ?> pm) {
                Map<String, Object> m = new LinkedHashMap<>((Map<String, Object>) em);
                ((Map<String, Object>) pm).forEach(m::putIfAbsent);
                merged.put("metrics", m);
                pipeline.forEach((k, v) -> { if (!"metrics".equals(k)) merged.put(k, v); });
            } else {
                merged.putAll(pipeline);
            }

            merged.put("sonar_available", true);
            merged.put("sonar_source", "PIPELINE");

            String resolvedBranch = stringVal(merged.get("branch"));
            if (isBlankStr(resolvedBranch)) {
                resolvedBranch = stringVal(merged.get("requested_branch"));
            }
            merged.put("branch_resolution",
                    com.backend.devsecopsplatform_backend.service.SonarBranchResolution.builder()
                            .sonarReachable(true)
                            .resolvedBranch(resolvedBranch)
                            .requestedBranch(resolvedBranch)
                            .availableBranches(isBlankStr(resolvedBranch) ? List.of() : List.of(resolvedBranch))
                            .build());

            return merged;
        }
        if (sonarJobState != SonarScanJobState.SUCCESS && sonarJobState != SonarScanJobState.MISSING) {
            return sonar != null ? sonar : Map.of();
        }
        return sonar != null ? sonar : Map.of();
    }

    private void enrichSonarFlatFromPipeline(
            Map<String, Object> sonarFlat,
            Map<String, Object> storedGate,
            Map<String, Object> summary
    ) {
        if (sonarFlat == null || sonarFlat.isEmpty()) {
            return;
        }
        Map<String, Object> pipelineFlat = sonarFlatMetrics(buildSonarFromPipelineArtifacts(storedGate, summary));
        if (!pipelineFlat.isEmpty()) {
            mergeSonarFlatPreferPipeline(sonarFlat, pipelineFlat);
        }
        Map<String, Object> sonarSection = extractSonarSectionFromSources(summary, storedGate);
        if (!sonarSection.isEmpty()) {
            applySonarSectionToFlat(sonarFlat, sonarSection);
        }
    }

    private void mergeSonarFlatPreferPipeline(Map<String, Object> target, Map<String, Object> pipelineFlat) {
        String[] preferHigher = {
                "software_quality_security_issues",
                "software_quality_reliability_issues",
                "software_quality_maintainability_issues",
                "blocker_violations", "critical_violations", "major_violations", "minor_violations",
                "bugs", "vulnerabilities", "code_smells", "security_hotspots", "ncloc"
        };
        for (String key : preferHigher) {
            int live = intVal(target.get(key));
            int pipe = intVal(pipelineFlat.get(key));
            if (pipe > live) {
                target.put(key, pipe);
            }
        }
        copySqRatingMetric(target, "software_quality_security_rating",
                target.get("software_quality_security_rating"),
                pipelineFlat.get("software_quality_security_rating"));
        copySqRatingMetric(target, "software_quality_reliability_rating",
                target.get("software_quality_reliability_rating"),
                pipelineFlat.get("software_quality_reliability_rating"));
        copySqRatingMetric(target, "software_quality_maintainability_rating",
                target.get("software_quality_maintainability_rating"),
                pipelineFlat.get("software_quality_maintainability_rating"));
        copySqRatingMetric(target, "security_rating",
                target.get("security_rating"), pipelineFlat.get("security_rating"));
        copySqRatingMetric(target, "reliability_rating",
                target.get("reliability_rating"), pipelineFlat.get("reliability_rating"));
        copySqRatingMetric(target, "sqale_rating",
                target.get("sqale_rating"), pipelineFlat.get("sqale_rating"));
        if (target.get("quality_gate_status") == null && pipelineFlat.get("quality_gate_status") != null) {
            target.put("quality_gate_status", pipelineFlat.get("quality_gate_status"));
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> extractSonarSectionFromSources(
            Map<String, Object> summary,
            Map<String, Object> storedGate
    ) {
        Map<String, Object> merged = new LinkedHashMap<>();
        if (summary != null && summary.get("sonar") instanceof Map<?, ?> fromSummary) {
            merged.putAll((Map<String, Object>) fromSummary);
        }
        if (storedGate != null) {
            if (storedGate.get("sonarSqSecurityIssues") != null) {
                merged.put("software_quality_security_issues", storedGate.get("sonarSqSecurityIssues"));
            }
            if (storedGate.get("sonarSqReliabilityIssues") != null) {
                merged.put("software_quality_reliability_issues", storedGate.get("sonarSqReliabilityIssues"));
            }
            if (storedGate.get("sonarSqMaintainabilityIssues") != null) {
                merged.put("software_quality_maintainability_issues", storedGate.get("sonarSqMaintainabilityIssues"));
            }
            copySqRatingMetric(merged, "software_quality_security_rating",
                    merged.get("software_quality_security_rating"),
                    storedGate.get("sonarSqSecurityRating"),
                    storedGate.get("sonarSecurityRating"));
            copySqRatingMetric(merged, "software_quality_reliability_rating",
                    merged.get("software_quality_reliability_rating"),
                    storedGate.get("sonarSqReliabilityRating"));
            copySqRatingMetric(merged, "software_quality_maintainability_rating",
                    merged.get("software_quality_maintainability_rating"),
                    storedGate.get("sonarSqMaintainabilityRating"));
            copySqRatingMetric(merged, "security_rating",
                    merged.get("security_rating"), storedGate.get("sonarSecurityRating"));
        }
        return merged;
    }

    private void applySonarSectionToFlat(Map<String, Object> sonarFlat, Map<String, Object> sonarSection) {
        copyIntMetric(sonarFlat, "software_quality_security_issues",
                sonarSection.get("software_quality_security_issues"));
        copyIntMetric(sonarFlat, "software_quality_reliability_issues",
                sonarSection.get("software_quality_reliability_issues"));
        copyIntMetric(sonarFlat, "software_quality_maintainability_issues",
                sonarSection.get("software_quality_maintainability_issues"));
        copySqRatingMetric(sonarFlat, "software_quality_security_rating",
                sonarFlat.get("software_quality_security_rating"),
                sonarSection.get("software_quality_security_rating"),
                sonarSection.get("security_rating"));
        copySqRatingMetric(sonarFlat, "software_quality_reliability_rating",
                sonarFlat.get("software_quality_reliability_rating"),
                sonarSection.get("software_quality_reliability_rating"),
                sonarSection.get("reliability_rating"));
        copySqRatingMetric(sonarFlat, "software_quality_maintainability_rating",
                sonarFlat.get("software_quality_maintainability_rating"),
                sonarSection.get("software_quality_maintainability_rating"),
                sonarSection.get("sqale_rating"));
        copySqRatingMetric(sonarFlat, "security_rating",
                sonarFlat.get("security_rating"), sonarSection.get("security_rating"));
        copySqRatingMetric(sonarFlat, "reliability_rating",
                sonarFlat.get("reliability_rating"), sonarSection.get("reliability_rating"));
        copySqRatingMetric(sonarFlat, "sqale_rating",
                sonarFlat.get("sqale_rating"), sonarSection.get("sqale_rating"));
        copyIntMetric(sonarFlat, "code_smells", sonarSection.get("code_smells"));
        copyIntMetric(sonarFlat, "blocker_violations",
                sonarSection.get("blocker_violations"), sonarSection.get("blockers"));
    }

    @SuppressWarnings("unchecked")
    private void applySoftwareQualityDimensionsToFlat(Map<String, Object> flat, Object dimensionsObj) {
        if (!(dimensionsObj instanceof List<?> list) || list.isEmpty()) {
            return;
        }
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> dim)) {
                continue;
            }
            String dimension = stringVal(dim.get("dimension"));
            if (dimension == null || dimension.isBlank()) {
                continue;
            }
            int issues = intVal(dim.get("issues"));
            Object rating = dim.get("rating");
            if (rating == null) {
                rating = dim.get("ratingValue");
            }
            switch (dimension.toUpperCase(Locale.ROOT)) {
                case "SECURITY" -> {
                    if (issues > intVal(flat.get("software_quality_security_issues"))) {
                        flat.put("software_quality_security_issues", issues);
                    }
                    copySqRatingMetric(flat, "software_quality_security_rating",
                            flat.get("software_quality_security_rating"), rating);
                }
                case "RELIABILITY" -> {
                    if (issues > intVal(flat.get("software_quality_reliability_issues"))) {
                        flat.put("software_quality_reliability_issues", issues);
                    }
                    copySqRatingMetric(flat, "software_quality_reliability_rating",
                            flat.get("software_quality_reliability_rating"), rating);
                }
                case "MAINTAINABILITY" -> {
                    if (issues > intVal(flat.get("software_quality_maintainability_issues"))) {
                        flat.put("software_quality_maintainability_issues", issues);
                    }
                    copySqRatingMetric(flat, "software_quality_maintainability_rating",
                            flat.get("software_quality_maintainability_rating"), rating);
                }
                default -> { }
            }
        }
    }

    private void persistSonarSqFieldsOnGate(Map<String, Object> gate, Map<String, Object> summary) {
        if (gate == null || summary == null || !(summary.get("sonar") instanceof Map<?, ?> sonar)) {
            return;
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> s = (Map<String, Object>) sonar;
        putPositiveOnGate(gate, "sonarSqSecurityIssues", s.get("software_quality_security_issues"));
        putPositiveOnGate(gate, "sonarSqReliabilityIssues", s.get("software_quality_reliability_issues"));
        putPositiveOnGate(gate, "sonarSqMaintainabilityIssues", s.get("software_quality_maintainability_issues"));
        Object secRate = firstNonNull(
                s.get("software_quality_security_rating"), s.get("security_rating"));
        Object relRate = firstNonNull(
                s.get("software_quality_reliability_rating"), s.get("reliability_rating"));
        Object maintRate = firstNonNull(
                s.get("software_quality_maintainability_rating"), s.get("sqale_rating"));
        if (secRate != null) {
            gate.put("sonarSqSecurityRating", SecurityScoringService.ratingToLetter(secRate));
        }
        if (relRate != null) {
            gate.put("sonarSqReliabilityRating", SecurityScoringService.ratingToLetter(relRate));
        }
        if (maintRate != null) {
            gate.put("sonarSqMaintainabilityRating", SecurityScoringService.ratingToLetter(maintRate));
        }
    }

    private void putPositiveOnGate(Map<String, Object> gate, String key, Object value) {
        int n = intVal(value);
        if (n > 0) {
            gate.put(key, n);
        }
    }

    private List<SoftwareQualityDimensionDto> finalizeSoftwareQualityDimensions(
            List<SoftwareQualityDimensionDto> current,
            Map<String, Object> sonarFlat,
            Map<String, Object> summary,
            Map<String, Object> storedGate
    ) {
        Map<String, Object> scratch = new LinkedHashMap<>(sonarFlat != null ? sonarFlat : Map.of());
        applySonarSectionToFlat(scratch, extractSonarSectionFromSources(summary, storedGate));
        List<SoftwareQualityDimensionDto> rebuilt = buildSoftwareQualityDimensions(scratch, true);
        if (rebuilt.isEmpty()) {
            return current != null ? current : List.of();
        }
        boolean rebuiltHasIssues = rebuilt.stream().anyMatch(d -> d.getIssues() > 0);
        boolean currentHasIssues = current != null && current.stream().anyMatch(d -> d.getIssues() > 0);
        if (rebuiltHasIssues || !currentHasIssues) {
            return rebuilt;
        }
        return current;
    }

    private void syncSoftwareQualityToSonarFlat(
            Map<String, Object> sonarFlat,
            List<SoftwareQualityDimensionDto> softwareQuality
    ) {
        if (sonarFlat == null || softwareQuality == null) {
            return;
        }
        for (SoftwareQualityDimensionDto dim : softwareQuality) {
            if (dim == null || dim.getDimension() == null) {
                continue;
            }
            switch (dim.getDimension().toUpperCase(Locale.ROOT)) {
                case "SECURITY" -> {
                    if (dim.getIssues() > 0) {
                        sonarFlat.put("software_quality_security_issues", dim.getIssues());
                    }
                    if (dim.getRating() != null) {
                        copySqRatingMetric(sonarFlat, "software_quality_security_rating", dim.getRating());
                        copySqRatingMetric(sonarFlat, "security_rating", dim.getRating());
                    }
                }
                case "RELIABILITY" -> {
                    if (dim.getIssues() > 0) {
                        sonarFlat.put("software_quality_reliability_issues", dim.getIssues());
                    }
                    if (dim.getRating() != null) {
                        copySqRatingMetric(sonarFlat, "software_quality_reliability_rating", dim.getRating());
                        copySqRatingMetric(sonarFlat, "reliability_rating", dim.getRating());
                    }
                }
                case "MAINTAINABILITY" -> {
                    if (dim.getIssues() > 0) {
                        sonarFlat.put("software_quality_maintainability_issues", dim.getIssues());
                    }
                    if (dim.getRating() != null) {
                        copySqRatingMetric(sonarFlat, "software_quality_maintainability_rating", dim.getRating());
                        copySqRatingMetric(sonarFlat, "sqale_rating", dim.getRating());
                    }
                }
                default -> { }
            }
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> mergeLiveSonarWithPipelineSq(Map<String, Object> live, Map<String, Object> pipeline) {
        if (live == null) {
            return pipeline != null ? pipeline : Map.of();
        }
        if (pipeline == null || pipeline.isEmpty()) {
            return live;
        }
        Map<String, Object> merged = new LinkedHashMap<>(live);
        Map<String, Object> liveFlat = sonarFlatMetrics(live);
        Map<String, Object> pipeFlat = sonarFlatMetrics(pipeline);
        Map<String, Object> combined = new LinkedHashMap<>(liveFlat);
        mergeSonarFlatPreferPipeline(combined, pipeFlat);
        merged.put("metrics", combined);
        pipeline.forEach((k, v) -> {
            if (!"metrics".equals(k)) {
                merged.putIfAbsent(k, v);
            }
        });
        return merged;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> buildSonarFromPipelineArtifacts(
            Map<String, Object> storedGate,
            Map<String, Object> summary
    ) {
        Map<String, Object> metrics = new LinkedHashMap<>();
        String qgStatus = null;

        if (storedGate != null) {
            qgStatus = firstNonBlank(
                    stringVal(storedGate.get("sonarQualityGate")),
                    stringVal(storedGate.get("sonar_quality_gate")));
            copyIntMetric(metrics, "blocker_violations", storedGate.get("sonarBlockers"), storedGate.get("sonar_blockers"));
            copyIntMetric(metrics, "critical_violations", storedGate.get("sonarCriticals"), storedGate.get("sonar_criticals"));
            copyIntMetric(metrics, "bugs", storedGate.get("sonarBugs"));
            copyIntMetric(metrics, "vulnerabilities", storedGate.get("sonarVulnerabilities"));
            copyIntMetric(metrics, "security_hotspots", storedGate.get("sonarHotspots"));
            copyIntMetric(metrics, "ncloc", storedGate.get("sonarNcloc"), storedGate.get("sonar_ncloc"));
            copyIntMetric(metrics, "software_quality_security_issues", storedGate.get("sonarSqSecurityIssues"));
            copyIntMetric(metrics, "software_quality_reliability_issues", storedGate.get("sonarSqReliabilityIssues"));
            copyIntMetric(metrics, "software_quality_maintainability_issues", storedGate.get("sonarSqMaintainabilityIssues"));
            copySqRatingMetric(metrics, "software_quality_security_rating", storedGate.get("sonarSqSecurityRating"));
            copySqRatingMetric(metrics, "software_quality_reliability_rating", storedGate.get("sonarSqReliabilityRating"));
            copySqRatingMetric(metrics, "software_quality_maintainability_rating", storedGate.get("sonarSqMaintainabilityRating"));
        }

        if (summary != null && summary.get("sonar") instanceof Map<?, ?> sonarSection) {
            Map<String, Object> s = (Map<String, Object>) sonarSection;
            if (qgStatus == null) {
                qgStatus = firstNonBlank(
                        stringVal(s.get("quality_gate")),
                        stringVal(s.get("quality_gate_status")));
            }
            copyIntMetric(metrics, "blocker_violations", s.get("blocker_violations"), s.get("blockers"));
            copyIntMetric(metrics, "critical_violations", s.get("critical_violations"), s.get("criticals"));
            copyIntMetric(metrics, "major_violations", s.get("major_violations"), s.get("majors"));
            copyIntMetric(metrics, "minor_violations", s.get("minor_violations"), s.get("minors"));
            copyIntMetric(metrics, "bugs", s.get("bugs"));
            copyIntMetric(metrics, "vulnerabilities", s.get("vulnerabilities"));
            copyIntMetric(metrics, "code_smells", s.get("code_smells"));
            copyIntMetric(metrics, "security_hotspots", s.get("hotspots"), s.get("security_hotspots"));
            copyIntMetric(metrics, "ncloc", s.get("ncloc"));
            mergeSonarSoftwareQualityMetrics(metrics, s, storedGate);
            if (s.get("coverage") != null) {
                metrics.putIfAbsent("coverage", s.get("coverage"));
            }
        } else if (storedGate != null) {
            mergeSonarSoftwareQualityMetrics(metrics, Map.of(), storedGate);
        }

        boolean hasQg = qgStatus != null && !qgStatus.isBlank() && !"N/A".equalsIgnoreCase(qgStatus);
        boolean hasMetrics = metrics.values().stream().anyMatch(v -> intVal(v) > 0 || (v != null && !String.valueOf(v).isBlank()));
        if (!hasQg && !hasMetrics) {
            return Map.of();
        }

        Map<String, Object> result = new LinkedHashMap<>();
        if (!metrics.isEmpty()) {
            result.put("metrics", metrics);
        }
        if (hasQg) {
            Map<String, Object> qg = new LinkedHashMap<>();
            qg.put("status", normalizeSonarQgStatus(qgStatus));
            result.put("quality_gate", qg);
        }
        return result;
    }

    private String normalizeSonarQgStatus(String raw) {
        if (raw == null || raw.isBlank()) {
            return raw;
        }
        return switch (raw.trim().toUpperCase(Locale.ROOT)) {
            case "PASSED", "PASS", "OK" -> "OK";
            case "FAILED", "FAIL", "ERROR" -> "ERROR";
            default -> raw.trim();
        };
    }

    private void mergeSonarSoftwareQualityMetrics(
            Map<String, Object> metrics,
            Map<String, Object> sonarSection,
            Map<String, Object> storedGate
    ) {
        if (sonarSection != null) {
            copyIntMetric(metrics, "software_quality_security_issues",
                    sonarSection.get("software_quality_security_issues"));
            copyIntMetric(metrics, "software_quality_reliability_issues",
                    sonarSection.get("software_quality_reliability_issues"));
            copyIntMetric(metrics, "software_quality_maintainability_issues",
                    sonarSection.get("software_quality_maintainability_issues"));
            copySqRatingMetric(metrics, "software_quality_security_rating",
                    sonarSection.get("software_quality_security_rating"));
            copySqRatingMetric(metrics, "software_quality_reliability_rating",
                    sonarSection.get("software_quality_reliability_rating"));
            copySqRatingMetric(metrics, "software_quality_maintainability_rating",
                    sonarSection.get("software_quality_maintainability_rating"));
            copyIntMetric(metrics, "software_quality_high_severity_issues",
                    sonarSection.get("software_quality_high_severity_issues"));
            copyIntMetric(metrics, "software_quality_medium_severity_issues",
                    sonarSection.get("software_quality_medium_severity_issues"));
            copyIntMetric(metrics, "software_quality_low_severity_issues",
                    sonarSection.get("software_quality_low_severity_issues"));
            copySqRatingMetric(metrics, "security_rating", sonarSection.get("security_rating"));
            copySqRatingMetric(metrics, "reliability_rating", sonarSection.get("reliability_rating"));
            copySqRatingMetric(metrics, "sqale_rating", sonarSection.get("sqale_rating"));
        }
        if (storedGate != null) {
            String legacySec = firstNonBlank(
                    stringVal(storedGate.get("sonarSecurityRating")),
                    stringVal(storedGate.get("sonar_security_rating")));
            if (!isBlankStr(legacySec)) {
                copySqRatingMetric(metrics, "security_rating", legacySec);
                if (!hasSqRating(metrics, "software_quality_security_rating")) {
                    copySqRatingMetric(metrics, "software_quality_security_rating", legacySec);
                }
            }
        }
    }

    private boolean hasSqRating(Map<String, Object> metrics, String key) {
        Object v = metrics.get(key);
        if (v == null) return false;
        if (intVal(v) > 0) return true;
        String s = stringVal(v);
        return s != null && !s.isBlank() && !"N/A".equalsIgnoreCase(s) && !"0".equals(s);
    }

    private void copySqRatingMetric(Map<String, Object> target, String key, Object... candidates) {
        for (Object c : candidates) {
            if (c == null) continue;
            String s = stringVal(c);
            if (s != null && !s.isBlank() && !"N/A".equalsIgnoreCase(s)) {
                target.put(key, c);
                return;
            }
            int n = intVal(c);
            if (n >= 1 && n <= 5) {
                target.put(key, n);
                return;
            }
        }
    }

    private void copyIntMetric(Map<String, Object> target, String key, Object... candidates) {
        for (Object c : candidates) {
            if (c == null) continue;
            int v = intVal(c);
            if (v >= 0 && (v > 0 || target.get(key) == null)) {
                target.put(key, v);
                if (v > 0) return;
            }
        }
    }

    private String firstNonBlank(String... values) {
        if (values == null) return null;
        for (String v : values) {
            if (v != null && !v.isBlank() && !"N/A".equalsIgnoreCase(v)) {
                return v;
            }
        }
        return null;
    }

    private List<String> buildVerdictExplanation(
            List<QualityGateStageDto> stages,
            Map<String, Object> summary,
            Map<String, Integer> bySeverity,
            List<HardGateViolationDto> hardGateViolations,
            List<String> indeterminateSources,
            String verdict,
            Map<String, Object> sonarFlat,
            SecurityScoreDto securityScore
    ) {
        List<String> lines = new ArrayList<>();

        if ("INDETERMINE".equals(verdict) && indeterminateSources != null && !indeterminateSources.isEmpty()) {
            lines.add("Impossible de garantir l'absence de vulnérabilité critique : "
                    + String.join(", ", indeterminateSources)
                    + " n'a/ont pas répondu. Relancez le service et actualisez.");
            return lines;
        }

        if (hardGateViolations != null && !hardGateViolations.isEmpty()) {
            lines.add("Hard gates violés — déploiement non recommandé :");
            for (HardGateViolationDto v : hardGateViolations) {
                lines.add("• " + v.getLabel() + " → " + v.getMessage());
            }
        }

        List<QualityGateStageDto> blocking = stages.stream()
                .filter(s -> s.isBlocking() && "FAIL".equals(s.getStatus()))
                .filter(s -> !isSecurityValidationStage(s.getName()))
                .toList();

        if (!blocking.isEmpty()) {
            lines.add("Seuils dépassés en échec (n'affecte pas le verdict si non hard gate) :");
            for (QualityGateStageDto s : blocking) {
                lines.add("• " + s.getName() + " (" + s.getToolLabel() + ") → " + s.getMessage());
            }
        }

        int highTotal = bySeverity.getOrDefault("high", 0);
        int medTotal = bySeverity.getOrDefault("medium", 0);
        if (highTotal > 0 || medTotal > 0) {
            lines.add(String.format(
                    "%d vulnérabilité(s) élevée(s) et %d moyenne(s) contribuent au score de posture.",
                    highTotal, medTotal));
        }

        if (securityScore != null) {
            lines.add(String.format(
                    "Score de posture : %d/100 (note %s) — basé sur la densité des findings (DefectDojo) et les ratings SonarQube.",
                    securityScore.getScore(), securityScore.getGrade()));
        }

        if (lines.isEmpty()) {
            if ("RECOMMENDED".equals(verdict)) {
                lines.add("Tous les hard gates sont respectés — aucune violation bloquante détectée.");
            } else {
                lines.add("Analyse basée sur les données live DefectDojo, SonarQube et le pipeline.");
            }
        }
        return lines;
    }

    private List<String> buildPracticalAdvice(
            String verdict,
            List<QualityGateStageDto> stages,
            Map<String, Object> summary,
            List<QualityGateToolMetricDto> tools,
            Map<String, Object> sonarFlat
    ) {
        List<String> advice = new ArrayList<>();
        int n = 1;

        for (QualityGateStageDto s : stages) {
            if (!s.isBlocking() || !"FAIL".equals(s.getStatus())) continue;
            if (isSecurityValidationStage(s.getName())) continue;
            advice.add(n++ + ". Corriger " + s.getToolLabel() + " : " + s.getMessage());
        }

        int secrets = intVal(summary.get("secrets"));
        if (secrets > 0) {
            advice.add(n++ + ". Révoquer les secrets exposés (" + secrets + ") et purger l'historique Git.");
        }

        Map<String, Object> container = mapVal(summary, "container");
        int contCrit = intVal(container.get("critical"));
        int contHigh = intVal(container.get("high"));
        if (contCrit > 0) {
            advice.add(n++ + ". Container (Grype) : corriger " + contCrit + " vulnérabilité(s) Critical sur l'image Docker.");
        } else if (contHigh > 0) {
            advice.add(n++ + ". Container (Grype) : réduire les " + contHigh + " vulnérabilité(s) High de l'image.");
        }

        int sonarBlockers = sonarViolationCount(sonarFlat, "blocker");
        if (sonarBlockers > 0) {
            advice.add(n++ + ". SonarQube : traiter " + sonarBlockers + " issue(s) Blocker (hard gate).");
        }

        Map<String, Object> sca = mapVal(summary, "sca");
        int scaHigh = intVal(sca.get("high"));
        if (scaHigh > 0 && scaHigh > 10) {
            advice.add(n++ + ". SCA (Trivy) : " + scaHigh + " vulnérabilité(s) High dans les dépendances — mettre à jour les packages.");
        }

        Map<String, Object> sast = mapVal(summary, "sast");
        int semgrepHigh = intVal(sast.get("semgrep_high"));
        if (semgrepHigh > 0) {
            advice.add(n++ + ". SAST (Semgrep) : corriger " + semgrepHigh + " finding(s) High dans le code source.");
        }

        for (QualityGateToolMetricDto t : tools) {
            if ("sonarqube".equals(t.getId())) {
                if (t.getCritical() > 0 || t.getHigh() > 0) {
                    advice.add(n++ + ". SonarQube : traiter " + t.getCritical() + " critique(s) et "
                            + t.getHigh() + " high signalés.");
                }
                continue;
            }
            if (t.getCritical() <= 0 && t.getHigh() <= 0) continue;
            advice.add(n++ + ". " + t.getLabel() + " : réduire les findings (" + t.getCritical()
                    + " critiques, " + t.getHigh() + " élevées).");
        }

        if (advice.isEmpty()) {
            if ("RECOMMENDED".equals(verdict)) {
                advice.add("1. Aucune action bloquante — vous pouvez déployer cette version en environnement éphémère.");
            } else if ("WITH_WARNINGS".equals(verdict)) {
                advice.add("1. Déploiement possible avec surveillance ; planifiez les corrections avant la production.");
            } else if ("INDETERMINE".equals(verdict)) {
                advice.add("1. Relancez les services indisponibles (DefectDojo, SonarQube) puis cliquez « Actualiser ».");
            } else {
                advice.add("1. Corrigez les hard gates violés puis relancez le pipeline.");
            }
        }
        return advice;
    }

    private String buildScoringNote() {
        return "Décision en deux niveaux : (1) hard gates déterministes — secrets Gitleaks, "
                + "vulnérabilités Critical DefectDojo, issues Blocker SonarQube, Quality Gate Sonar ERROR "
                + "(indéterminé si la source est indisponible) ; "
                + "(2) score de posture informatif (densité / 1000 LOC via ncloc SonarQube) "
                + "uniquement si tous les hard gates passent — départage RECOMMENDED vs WITH_WARNINGS. "
                + "Le verdict CI security-validation n'est pas utilisé pour la décision.";
    }

    private String buildSummaryText(
            String verdict,
            Map<String, Integer> bySeverity,
            List<QualityGateStageDto> stages,
            SecurityScoreDto securityScore,
            SecurityScoringService.HardGateEvaluation hardGates,
            String incompleteMessage
    ) {
        if ("INDETERMINE".equals(verdict) && incompleteMessage != null) {
            return incompleteMessage;
        }
        if ("NOT_RECOMMENDED".equals(verdict) && hardGates != null && hardGates.summaryMessage() != null) {
            return hardGates.summaryMessage();
        }

        int total = bySeverity.values().stream().mapToInt(Integer::intValue).sum();
        long blocking = stages.stream().filter(s -> s.isBlocking() && "FAIL".equals(s.getStatus())).count();
        long warn = stages.stream().filter(s -> "WARN".equals(s.getStatus())).count();
        int crit = bySeverity.getOrDefault("critical", 0);
        int high = bySeverity.getOrDefault("high", 0);
        int med = bySeverity.getOrDefault("medium", 0);

        String verdictFr = switch (verdict) {
            case "RECOMMENDED" -> "Déployable";
            case "WITH_WARNINGS" -> "Déployable avec surveillance";
            case "NOT_RECOMMENDED" -> "Déploiement non recommandé";
            case "INDETERMINE" -> "Vérification incomplète";
            default -> "Inconnu";
        };

        String scorePart = securityScore != null
                ? String.format(" · Score posture %d/100 (%s)", securityScore.getScore(), securityScore.getGrade())
                : "";
        return String.format(
                "%s%s — %d vulnérabilité(s) ouvertes · %d critiques · %d élevées · %d moyennes — %d seuil(s) dépassé(s) · %d avertissement(s)",
                verdictFr, scorePart, total, crit, high, med, blocking, warn
        );
    }

    private String buildTrendNote(DefectDojoDashboard2Response dd) {
        if (dd == null || dd.getTrendPoints() == null || dd.getTrendPoints().isEmpty()) {
            return null;
        }
        var last = dd.getTrendPoints().get(dd.getTrendPoints().size() - 1);
        if (last.getNewFindings() > 0) {
            return "+" + last.getNewFindings() + " nouvelle(s) vulnérabilité(s) sur la période récente.";
        }
        if (last.getResolved() > 0) {
            return last.getResolved() + " vulnérabilité(s) résolue(s) récemment.";
        }
        return null;
    }

    private String mapVerdict(String recommendation) {
        if (recommendation == null) return "UNKNOWN";
        return switch (recommendation) {
            case "RECOMMANDE" -> "RECOMMENDED";
            case "DEPLOY_WITH_WARNINGS" -> "WITH_WARNINGS";
            case "NON_RECOMMANDE" -> "NOT_RECOMMENDED";
            default -> recommendation;
        };
    }

    private String mapStageStatus(Object verdict) {
        if (verdict == null) return "WARN";
        String v = String.valueOf(verdict);
        if ("RECOMMENDED".equals(v) || "RECOMMANDE".equals(v)) return "PASS";
        if ("WITH_WARNINGS".equals(v) || "DEPLOY_WITH_WARNINGS".equals(v)) return "WARN";
        if ("NOT_RECOMMENDED".equals(v) || "NON_RECOMMANDE".equals(v)) return "FAIL";
        return "WARN";
    }

    private User currentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getName() == null) {
            throw new IllegalArgumentException("Utilisateur non authentifié");
        }
        return userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new IllegalArgumentException("Utilisateur non trouvé"));
    }

    private String normalizeBranch(String branch) {
        if (branch == null || branch.isBlank() || "all".equalsIgnoreCase(branch) || "__global__".equals(branch)) {
            return null;
        }
        return branch.trim();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> mapVal(Map<String, Object> parent, String key) {
        if (parent == null) return Map.of();
        Object v = parent.get(key);
        if (v instanceof Map<?, ?> m) return (Map<String, Object>) m;
        return Map.of();
    }

    private int intVal(Object o) {
        if (o == null) return 0;
        if (o instanceof Number n) return n.intValue();
        try {
            return Integer.parseInt(String.valueOf(o));
        } catch (Exception e) {
            return 0;
        }
    }

    private double doubleVal(Object o) {
        if (o == null) return 0;
        if (o instanceof Number n) return n.doubleValue();
        try {
            return Double.parseDouble(String.valueOf(o));
        } catch (Exception e) {
            return 0;
        }
    }

    private String stringVal(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    private static boolean isBlankStr(String s) {
        return s == null || s.isBlank();
    }

    private static String nullIfBlank(String s) {
        return isBlankStr(s) ? null : s;
    }
}
