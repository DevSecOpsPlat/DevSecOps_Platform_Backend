package com.backend.devsecopsplatform_backend.service.qualitygate;

import com.backend.devsecopsplatform_backend.entity.Application;
import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.QualityGateSnapshot;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.ApplicationRepository;
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
    public static final String SNAPSHOT_SOURCE_MANUAL = "MANUAL";

    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final FindingOccurrenceRepository findingOccurrenceRepository;
    private final EphemeralEnvironmentRepository environmentRepository;
    private final ApplicationRepository applicationRepository;
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
        gate.put("dastHigh", request.getDastHigh());
        if (request.getSummary() != null) {
            gate.put("summary", objectMapper.convertValue(request.getSummary(), Map.class));
        }
        if (request.getQualityGate() != null) {
            gate.put("qualityGate", objectMapper.convertValue(request.getQualityGate(), Map.class));
        }

        execution.setQualityGateJson(gate);
        pipelineExecutionRepository.save(execution);
        log.info("Quality gate enregistré pour env {} pipeline {}", request.getEnvironmentId(), request.getPipelineId());
        try {
            buildAndPersistSnapshot(env.getApplication(), env.getGitBranch(), execution, true,
                    SNAPSHOT_SOURCE_CI_INGEST);
        } catch (Exception e) {
            log.warn("Snapshot quality gate non enregistré pour env {}: {}", request.getEnvironmentId(), e.getMessage());
        }
    }

    @Transactional
    public void refreshSnapshotForEnvironment(UUID applicationId, UUID environmentId) {
        User user = currentUser();
        applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));
        EphemeralEnvironment env = environmentRepository.findByIdWithApplication(environmentId)
                .orElseThrow(() -> new IllegalArgumentException("Environnement introuvable"));
        if (env.getApplication() == null || !applicationId.equals(env.getApplication().getId())) {
            throw new IllegalArgumentException("Environnement introuvable pour cette application");
        }
        PipelineExecution execution = pipelineExecutionRepository
                .findByEnvironmentIdAndApplicationId(environmentId, applicationId)
                .orElseThrow(() -> new IllegalArgumentException("Aucune exécution pipeline pour cet environnement"));
        buildAndPersistSnapshot(env.getApplication(), env.getGitBranch(), execution, false, SNAPSHOT_SOURCE_MANUAL);
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
        EphemeralEnvironment env = environmentRepository.findByIdWithApplication(environmentId)
                .orElseThrow(() -> new IllegalArgumentException("Environnement introuvable"));
        if (env.getApplication() == null || !applicationId.equals(env.getApplication().getId())) {
            throw new IllegalArgumentException("Environnement introuvable pour cette application");
        }
        PipelineExecution execution = pipelineExecutionRepository
                .findByEnvironmentIdAndApplicationId(environmentId, applicationId)
                .orElseThrow(() -> new IllegalArgumentException("Aucune exécution pipeline pour cet environnement"));

        buildAndPersistSnapshot(env.getApplication(), env.getGitBranch(), execution, false, SNAPSHOT_SOURCE_MANUAL);

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
        Application app = execution.getEnvironment().getApplication();
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
        for (EphemeralEnvironment env : environmentRepository.findByApplicationWithPipeline(applicationId, null)) {
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
                .findByIdWithEnvironmentAndApplication(execution.getId())
                .orElse(execution);
        if (loaded.getEnvironment() == null || loaded.getEnvironment().getApplication() == null) {
            log.debug("Snapshot QG ignoré : environnement ou application manquant pour exec {}", loaded.getId());
            return;
        }
        try {
            buildAndPersistSnapshot(
                    loaded.getEnvironment().getApplication(),
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
        Application app = applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));

        if (snapshotId != null) {
            return getSnapshotById(applicationId, snapshotId);
        }

        String effectiveBranch = normalizeBranch(branch);
        PipelineExecution execution;

        if (environmentId != null) {
            environmentRepository.findByIdAndApplication_Id(environmentId, applicationId)
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
                    return stored;
                }
                return buildMissingSnapshotResult(app, effectiveBranch, environmentId, execution);
            }
        } else {
            execution = findLatestExecution(applicationId, effectiveBranch);
            if (!refresh) {
                QualityGateResultDto stored = tryLoadSnapshotFromDb(applicationId, effectiveBranch, execution);
                if (stored != null) {
                    return stored;
                }
                return buildMissingSnapshotResultForBranch(app, effectiveBranch, execution);
            }
        }

        // refresh=true uniquement : reconstruction live (DefectDojo + SonarQube)
        UUID effectiveEnvironmentId = environmentId;
        DefectDojoDashboard2Response dd = null;
        try {
            dd = defectDojoService.getDashboard2(applicationId, effectiveBranch, effectiveEnvironmentId);
        } catch (Exception e) {
            log.warn("DefectDojo indisponible pour quality gate: {}", e.getMessage());
        }

        Map<String, Object> sonar = fetchSonarForQualityGate(app, effectiveBranch);
        return buildResult(app, effectiveBranch, execution, dd, sonar, effectiveEnvironmentId);
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
            environmentRepository.findByIdAndApplication_Id(environmentId, applicationId)
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
        applicationRepository.findByIdAndCreatedBy(applicationId, user)
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
        return dto;
    }

    @Transactional(readOnly = true)
    public List<QualityGateEnvironmentOptionDto> listEnvironments(UUID applicationId, String branch) {
        User user = currentUser();
        applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));

        String effectiveBranch = normalizeBranch(branch);
        // Tous les environnements de l'app (pas de filtre branche) pour ne pas masquer un nouveau test.
        List<EphemeralEnvironment> envs = environmentRepository.findByApplicationWithPipeline(
                applicationId, null);

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
            Application app,
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
        Map<String, Object> sonar = fetchSonarForQualityGate(app, branch);
        QualityGateResultDto result = buildResult(app, branch, execution, dd, sonar, environmentId);
        persistDisplaySnapshot(execution, result, appendHistory);
        saveSnapshotTable(app.getId(), execution.getEnvironment().getId(), execution, branch, source, result);
    }

    private QualityGateResultDto loadSnapshotForEnvironment(UUID environmentId, PipelineExecution execution) {
        Optional<QualityGateSnapshot> fromTable = qualityGateSnapshotRepository
                .findFirstByEnvironmentIdOrderByCreatedAtDesc(environmentId);
        if (fromTable.isPresent()) {
            return fromSnapshotEntity(fromTable.get());
        }
        return loadStoredDisplaySnapshot(execution);
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
        if (dto.getEvaluatedAt() == null) {
            dto.setEvaluatedAt(row.getEvaluatedAt());
        }
        if (dto.getBranch() == null || dto.getBranch().isBlank()) {
            dto.setBranch(row.getBranch());
        }
        return dto;
    }

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

    private Map<String, Object> fetchSonarForQualityGate(Application app, String branch) {
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
            Application app,
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

    private <T> T runWithSnapshotAuth(Application app, PipelineExecution execution, Supplier<T> action) {
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
    private String resolveSnapshotUsername(Application app, PipelineExecution execution) {
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
    public String generateAiInsight(UUID applicationId, String branch) {
        QualityGateResultDto result = getForApplication(applicationId, branch);
        try {
            String json = objectMapper.writeValueAsString(buildAiInsightContext(result));
            return aiAnalysisService.generateQualityGateInsight(json);
        } catch (Exception e) {
            log.warn("Sérialisation quality gate pour IA: {}", e.getMessage());
            return null;
        }
    }

    /** Contexte IA ciblé (score, SQ, stages bloquants) — évite un JSON brut trop volumineux. */
    private Map<String, Object> buildAiInsightContext(QualityGateResultDto result) {
        Map<String, Object> ctx = new LinkedHashMap<>();
        ctx.put("branch", result.getBranch());
        ctx.put("verdict", result.getVerdict());
        ctx.put("ciVerdict", result.getCiVerdict());
        ctx.put("verdictSource", result.getVerdictSource());
        ctx.put("summary", result.getSummary());
        ctx.put("securityScore", result.getSecurityScore());
        Map<String, Object> metricsCtx = new LinkedHashMap<>();
        if (result.getMetrics() != null) {
            metricsCtx.put("bySeverity", result.getMetrics().get("bySeverity") != null
                    ? result.getMetrics().get("bySeverity") : Map.of());
            metricsCtx.put("totalVulnerabilities", result.getMetrics().get("totalVulnerabilities"));
            metricsCtx.put("secrets", result.getMetrics().get("secrets"));
        }
        ctx.put("metrics", metricsCtx);
        ctx.put("softwareQuality", result.getSoftwareQuality());
        ctx.put("softwareQualitySeverity", result.getSoftwareQualitySeverity());
        ctx.put("sonarAvailability", result.getSonarAvailability());
        ctx.put("sonarQube", result.getMetrics() != null ? result.getMetrics().get("sonarQube") : null);
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

    @Transactional(readOnly = true)
    public List<String> listBranches(UUID applicationId) {
        User user = currentUser();
        Application app = applicationRepository.findByIdAndCreatedBy(applicationId, user)
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
        environmentRepository.findByApplication_Id(applicationId).stream()
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
            Application app,
            String branch,
            PipelineExecution execution,
            DefectDojoDashboard2Response dd,
            Map<String, Object> sonar,
            UUID environmentId
    ) {
        Map<String, Object> storedGate = execution != null ? execution.getQualityGateJson() : null;
        Map<String, Object> summary = resolveEffectiveSummary(execution, storedGate);
        boolean hasSummary = !summary.isEmpty();
        UUID scopedEnvId = environmentId != null
                ? environmentId
                : (execution != null && execution.getEnvironment() != null
                        ? execution.getEnvironment().getId() : null);
        boolean usePipelineSummary = hasSummary;
        Map<String, Integer> ddByTool = dd != null ? dd.getByTool() : null;
        if (usePipelineSummary && (ddByTool == null || ddByTool.values().stream().allMatch(v -> v == null || v == 0))) {
            ddByTool = null;
        }

        List<Map<String, Object>> jobs = execution != null
                ? getJobsFromStagesJson(execution)
                : List.of();

        Map<String, Object> sonarFlat = sonarFlatMetrics(sonar);
        SonarAvailabilityDto sonarAvailability = buildSonarAvailability(sonar, app);
        List<SoftwareQualityDimensionDto> softwareQuality = buildSoftwareQualityDimensions(
                sonarFlat, sonarAvailability.isAvailable());
        Map<String, Integer> softwareQualitySeverity = buildSoftwareQualitySeverity(sonarFlat);

        List<QualityGateToolMetricDto> toolMetrics = buildToolMetrics(
                summary, ddByTool, sonarFlat, usePipelineSummary, softwareQuality);
        Map<String, Integer> bySeverity = buildBySeverity(dd, summary, toolMetrics, scopedEnvId != null);

        Map<String, Object> effectiveSummary = usePipelineSummary ? summary : syntheticSummaryFromTools(toolMetrics);
        List<QualityGateStageDto> stages = buildStages(jobs, effectiveSummary, storedGate, sonarFlat, usePipelineSummary || !toolMetrics.isEmpty());
        attachStageToTools(toolMetrics, stages);
        Map<String, Object> metrics = buildMetrics(
                bySeverity, effectiveSummary, stages, sonarFlat, dd, softwareQuality, softwareQualitySeverity);

        String ciVerdictRaw = storedGate != null ? stringVal(storedGate.get("verdict")) : null;
        if (ciVerdictRaw == null && storedGate != null) {
            ciVerdictRaw = mapVerdict(stringVal(storedGate.get("recommendation")));
        }
        String ciVerdict = normalizeCiVerdict(ciVerdictRaw);

        SecurityScoreInput scoreInput = buildSecurityScoreInput(
                bySeverity, effectiveSummary, stages, sonarFlat, sonar, storedGate);
        SecurityScoreDto securityScore = securityScoringService.compute(scoreInput);

        VerdictResolution verdictResolution = resolveVerdictWithSource(
                ciVerdict, securityScore, stages, effectiveSummary);
        String verdict = verdictResolution.verdict();
        String verdictSource = verdictResolution.source();

        List<String> verdictExplanation = buildVerdictExplanation(
                stages, effectiveSummary, bySeverity, verdict, sonarFlat, securityScore);
        List<String> practicalAdvice = buildPracticalAdvice(verdict, stages, effectiveSummary, toolMetrics, sonarFlat);
        String scoringNote = buildScoringNote();
        String summaryText = buildSummaryText(verdict, bySeverity, stages, securityScore);

        List<String> availableBranches = mergeAvailableBranches(branch, sonar, dd);

        String pipelineId = execution != null && execution.getGitlabPipelineId() != null
                ? String.valueOf(execution.getGitlabPipelineId())
                : storedGate != null ? stringVal(storedGate.get("pipelineId")) : null;

        String webUrl = null;
        String pipelineStatus = null;
        if (execution != null && execution.getStagesJson() != null) {
            webUrl = stringVal(execution.getStagesJson().get("webUrl"));
            pipelineStatus = stringVal(execution.getStagesJson().get("status"));
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

        return QualityGateResultDto.builder()
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
    }

    private record VerdictResolution(String verdict, String source) {}

    private QualityGateResultDto buildMissingSnapshotResult(
            Application app,
            String branch,
            UUID environmentId,
            PipelineExecution execution
    ) {
        String pipelineId = execution != null && execution.getGitlabPipelineId() != null
                ? String.valueOf(execution.getGitlabPipelineId()) : null;
        String pipelineStatus = execution != null && execution.getStatus() != null
                ? execution.getStatus().name() : null;
        String tag = DefectDojoService.environmentTag(environmentId);
        return QualityGateResultDto.builder()
                .applicationId(app.getId())
                .branch(branch)
                .environmentId(environmentId)
                .pipelineId(pipelineId)
                .pipelineStatus(pipelineStatus)
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
                .summary("Aucun snapshot conservé pour cet environnement (tag DefectDojo « "
                        + tag + " »). "
                        + (execution != null && execution.getStatus() != null && !execution.getStatus().isFinished()
                        ? "Pipeline encore en cours — le snapshot sera créé après import-defectdojo ou à la fin du pipeline."
                        : "Utilisez « Actualiser » ou POST /api/quality-gate/snapshots/backfill pour reconstruire depuis les APIs."))
                .detailedRecommendations(List.of())
                .practicalAdvice(List.of())
                .verdictExplanation(List.of())
                .availableBranches(listBranches(app.getId()))
                .source("snapshot-missing")
                .build();
    }

    private QualityGateResultDto buildMissingSnapshotResultForBranch(
            Application app,
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

    /** summary.json du pipeline, sinon comptages BDD des findings ingérés. */
    private Map<String, Object> resolveEffectiveSummary(
            PipelineExecution execution,
            Map<String, Object> storedGate
    ) {
        Map<String, Object> fromGate = extractSummary(storedGate);
        if (!fromGate.isEmpty()) {
            return fromGate;
        }
        if (execution != null && execution.getGitlabPipelineId() != null) {
            Map<String, Object> fromFindings = buildSummaryFromPipelineFindings(execution.getGitlabPipelineId());
            if (!fromFindings.isEmpty()) {
                return fromFindings;
            }
        }
        return Map.of();
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
        Object bySev = flat.get("by_severity");
        if (bySev == null && sonar.get("open_issues_by_severity") instanceof Map<?, ?> m) {
            flat.put("by_severity", m);
        }
        return flat;
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

    private Map<String, Integer> buildBySeverity(
            DefectDojoDashboard2Response dd,
            Map<String, Object> summary,
            List<QualityGateToolMetricDto> tools,
            boolean environmentScoped
    ) {
        Map<String, Integer> out = new LinkedHashMap<>();
        out.put("critical", 0);
        out.put("high", 0);
        out.put("medium", 0);
        out.put("low", 0);
        out.put("info", 0);

        if (dd != null && dd.getBySeverity() != null && !dd.getBySeverity().isEmpty()) {
            out.put("critical", dd.getBySeverity().getOrDefault("Critical", 0));
            out.put("high", dd.getBySeverity().getOrDefault("High", 0));
            out.put("medium", dd.getBySeverity().getOrDefault("Medium", 0));
            out.put("low", dd.getBySeverity().getOrDefault("Low", 0));
            out.put("info", dd.getBySeverity().getOrDefault("Info", 0));
            if (dd.getTotalOpen() > 0 || environmentScoped) {
                return out;
            }
        }

        if (!summary.isEmpty()) {
            Map<String, Object> sca = mapVal(summary, "sca");
            Map<String, Object> container = mapVal(summary, "container");
            Map<String, Object> sast = mapVal(summary, "sast");
            Map<String, Object> dast = mapVal(summary, "dast");
            out.put("critical", intVal(sca.get("critical")) + intVal(container.get("critical")));
            out.put("high", intVal(sca.get("high")) + intVal(container.get("high"))
                    + intVal(sast.get("semgrep_high")) + intVal(dast.get("high")));
            out.put("medium", intVal(sca.get("medium")) + intVal(sast.get("semgrep_medium")) + intVal(dast.get("medium")));
            out.put("low", intVal(sca.get("low")) + intVal(dast.get("low")));
            return out;
        }

        for (QualityGateToolMetricDto t : tools) {
            out.put("critical", out.get("critical") + t.getCritical());
            out.put("high", out.get("high") + t.getHigh());
            out.put("medium", out.get("medium") + t.getMedium());
            out.put("low", out.get("low") + t.getLow());
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
                .source(hasSummary ? "pipeline-summary" : "defectdojo")
                .raw(sca).build());

        int semHigh = hasSummary ? intVal(sast.get("semgrep_high")) : countByToolMatchers(ddByTool, "semgrep");
        int semMed = hasSummary ? intVal(sast.get("semgrep_medium")) : 0;
        tools.add(QualityGateToolMetricDto.builder()
                .id("semgrep").label("Semgrep").type("SAST")
                .critical(0).high(semHigh).medium(semMed).low(0)
                .total(semHigh + semMed)
                .source(hasSummary ? "pipeline-summary" : "defectdojo")
                .raw(sast).build());

        int secrets = hasSummary ? intVal(summary.get("secrets")) : countByToolMatchers(ddByTool, "gitleaks", "secret");
        tools.add(QualityGateToolMetricDto.builder()
                .id("gitleaks").label("Gitleaks").type("Secrets")
                .critical(secrets > 0 ? secrets : 0).high(0).medium(0).low(0)
                .total(secrets)
                .source(hasSummary ? "pipeline-summary" : "defectdojo")
                .build());

        int contCrit = hasSummary ? intVal(container.get("critical")) : 0;
        int contHigh = hasSummary ? intVal(container.get("high")) : countByToolMatchers(ddByTool, "grype", "container");
        tools.add(QualityGateToolMetricDto.builder()
                .id("grype").label("Grype").type("Container")
                .critical(contCrit).high(contHigh).medium(0).low(0)
                .total(contCrit + contHigh)
                .source(hasSummary ? "pipeline-summary" : "defectdojo")
                .raw(container).build());

        int checkov = hasSummary ? intVal(iac.get("checkov_failed")) : countByToolMatchers(ddByTool, "checkov");
        tools.add(QualityGateToolMetricDto.builder()
                .id("checkov").label("Checkov").type("IaC")
                .critical(0).high(checkov).medium(0).low(0)
                .total(checkov)
                .source(hasSummary ? "pipeline-summary" : "defectdojo")
                .raw(iac).build());

        int dastHigh = hasSummary ? intVal(dast.get("high")) : countByToolMatchers(ddByTool, "zap", "dast");
        int dastMed = hasSummary ? intVal(dast.get("medium")) : 0;
        tools.add(QualityGateToolMetricDto.builder()
                .id("zap").label("OWASP ZAP").type("DAST")
                .critical(0).high(dastHigh).medium(dastMed).low(intVal(dast.get("low")))
                .total(dastHigh + dastMed)
                .source(hasSummary ? "pipeline-summary" : "defectdojo")
                .raw(dast).build());

        int hadolint = hasSummary ? intVal(sast.get("hadolint_errors")) : countByToolMatchers(ddByTool, "hadolint");
        tools.add(QualityGateToolMetricDto.builder()
                .id("hadolint").label("Hadolint").type("Lint")
                .critical(0).high(hadolint).medium(0).low(0)
                .total(hadolint)
                .source(hasSummary ? "pipeline-summary" : "defectdojo")
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
                .source("sonarqube-measures-api")
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
                stage = stage.toBuilder()
                        .status("SKIPPED")
                        .statusLabel("Ignoré")
                        .message("(pas exécuté car gate précédent bloqué)")
                        .blocking(false)
                        .build();
            }
            stages.add(stage);
        }

        if (stages.isEmpty() && storedGate != null) {
            stages.add(QualityGateStageDto.builder()
                    .name("security-validation")
                    .toolLabel("Security Validation")
                    .status(mapStageStatus(storedGate.get("verdict")))
                    .statusLabel(statusLabel(mapStageStatus(storedGate.get("verdict"))))
                    .message("Verdict CI : " + storedGate.get("recommendation"))
                    .blocking("FAIL".equals(mapStageStatus(storedGate.get("verdict"))))
                    .build());
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
            if (stage == null) stage = stringVal(job.get("name"));
            if (stage != null) {
                jobsByStage.putIfAbsent(stage.toLowerCase(Locale.ROOT), job);
            }
        }
        return jobsByStage;
    }

    private Map<String, Object> findJob(Map<String, Map<String, Object>> jobsByStage, String stageName) {
        if (jobsByStage.containsKey(stageName)) {
            return jobsByStage.get(stageName);
        }
        for (Map.Entry<String, Map<String, Object>> e : jobsByStage.entrySet()) {
            if (e.getKey().contains(stageName) || stageName.contains(e.getKey())) {
                return e.getValue();
            }
        }
        return null;
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
        String gitlabStatus = job != null ? stringVal(job.get("status")) : null;
        String toolLabel = toolLabelForStage(lower);
        Map<String, Object> stageMetrics = new LinkedHashMap<>();

        if (pipelineBlocked && CASCADE_AFTER_BLOCK.contains(lower)) {
            return baseStage(stageName, toolLabel, job)
                    .status("SKIPPED").statusLabel("Ignoré")
                    .message("(pas exécuté car gate précédent bloqué)")
                    .blocking(false).metrics(stageMetrics).build();
        }

        if (lower.contains("security-validation")) {
            String ciRec = storedGate != null ? stringVal(storedGate.get("recommendation")) : null;
            String st = mapStageStatus(storedGate != null ? storedGate.get("verdict") : null);
            String msg = ciRec != null
                    ? "Le stage a produit le verdict " + ciRec
                    : "Évaluation finale du quality gate CI";
            return baseStage(stageName, toolLabel, job)
                    .status(st).statusLabel(statusLabel(st))
                    .message(msg)
                    .blocking("FAIL".equals(st))
                    .metrics(stageMetrics).build();
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
            boolean qgOk = "OK".equalsIgnoreCase(qgStr);
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
            String st = gitlabFailed(gitlabStatus) ? "FAIL" : (gitlabSkipped(gitlabStatus) ? "SKIPPED" : "PASS");
            return baseStage(stageName, toolLabel, job)
                    .status(st).statusLabel(statusLabel(st))
                    .message("PASS".equals(st) ? "Clone + détection des langages OK" : stageDefaultMessage(st, gitlabStatus))
                    .blocking("FAIL".equals(st)).metrics(stageMetrics).build();
        }

        if (lower.contains("build")) {
            String st = gitlabFailed(gitlabStatus) ? "FAIL" : (gitlabSkipped(gitlabStatus) ? "SKIPPED" : "PASS");
            return baseStage(stageName, toolLabel, job)
                    .status(st).statusLabel(statusLabel(st))
                    .message("PASS".equals(st) ? "Image Docker construite" : stageDefaultMessage(st, gitlabStatus))
                    .blocking(false).metrics(stageMetrics).build();
        }

        if (lower.contains("report") || lower.contains("aggregate") || lower.contains("import-defectdojo")) {
            String st = gitlabFailed(gitlabStatus) ? "FAIL" : (gitlabSkipped(gitlabStatus) ? "SKIPPED" : "PASS");
            return baseStage(stageName, toolLabel, job)
                    .status(st).statusLabel(statusLabel(st))
                    .message("PASS".equals(st) ? "Aggrégation des rapports OK" : stageDefaultMessage(st, gitlabStatus))
                    .blocking(false).metrics(stageMetrics).build();
        }

        String st = gitlabFailed(gitlabStatus) ? "FAIL" : (gitlabSkipped(gitlabStatus) ? "SKIPPED" : "PASS");
        return baseStage(stageName, toolLabel, job)
                .status(st).statusLabel(statusLabel(st))
                .message(stageDefaultMessage(st, gitlabStatus))
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

    private String toolLabelForStage(String lower) {
        if (lower.contains("sca") || lower.contains("trivy")) return "Sca (Trivy FS)";
        if (lower.contains("sast")) return "Sast (Semgrep)";
        if (lower.contains("secret")) return "Secrets (Gitleaks)";
        if (lower.contains("container")) return "Container-Scan (Grype)";
        if (lower.contains("sonar")) return "Code-Analysis (SonarQube)";
        if (lower.contains("iac")) return "IaC (Checkov)";
        if (lower.contains("zap")) return "Zap-Scan (DAST)";
        if (lower.contains("security-validation")) return "Security-Validation";
        if (lower.contains("setup") || lower.contains("clone")) return "Setup";
        if (lower.contains("build")) return "Build";
        if (lower.contains("push")) return "Push-Image";
        if (lower.contains("deploy")) return "Deploy-K8s";
        if (lower.contains("report") || lower.contains("aggregate")) return "Reporting";
        return capitalizeStage(lower);
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
     * Priorité au job GitLab. Si le job a réussi, le stage reflète PASS (sauf secrets bloquants).
     */
    private String mergeGitlab(String gateStatus, String gitlabStatus, boolean respectGateOnGitlabSuccess) {
        if (gitlabFailed(gitlabStatus)) return "FAIL";
        if (gitlabSkipped(gitlabStatus)) return "SKIPPED";
        if (gitlabSuccess(gitlabStatus)) {
            if (respectGateOnGitlabSuccess) {
                return gateStatus;
            }
            if ("FAIL".equals(gateStatus)) {
                return "PASS";
            }
            return gateStatus != null ? gateStatus : "PASS";
        }
        return gateStatus != null ? gateStatus : "PASS";
    }

    private boolean gitlabSuccess(String gitlabStatus) {
        return gitlabStatus != null
                && ("success".equalsIgnoreCase(gitlabStatus) || "passed".equalsIgnoreCase(gitlabStatus));
    }

    private String overrideByGitlab(String gateStatus, String gitlabStatus) {
        if (gitlabFailed(gitlabStatus)) return "FAIL";
        if (gitlabSkipped(gitlabStatus)) return "SKIPPED";
        return gateStatus;
    }

    private boolean gitlabFailed(String gitlabStatus) {
        return "failed".equalsIgnoreCase(gitlabStatus);
    }

    private boolean gitlabSkipped(String gitlabStatus) {
        return gitlabStatus != null && ("skipped".equalsIgnoreCase(gitlabStatus) || "canceled".equalsIgnoreCase(gitlabStatus));
    }

    private String stageDefaultMessage(String st, String gitlabStatus) {
        if ("SKIPPED".equals(st)) return "Étape ignorée";
        if ("FAIL".equals(st)) return "Job échoué dans GitLab";
        return "OK";
    }

    private String statusLabel(String status) {
        return switch (status) {
            case "PASS" -> "Réussi";
            case "WARN" -> "Avertissement";
            case "FAIL" -> "ÉCHEC";
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
            Map<String, Integer> softwareQualitySeverity
    ) {
        Map<String, Object> metrics = new LinkedHashMap<>();
        int totalOpen = dd != null && dd.getTotalOpen() > 0
                ? dd.getTotalOpen()
                : bySeverity.values().stream().mapToInt(Integer::intValue).sum();
        metrics.put("totalVulnerabilities", totalOpen);
        metrics.put("bySeverity", bySeverity);

        long blockingFails = stages.stream()
                .filter(s -> "FAIL".equals(s.getStatus()) && s.isBlocking())
                .count();
        long warnStages = stages.stream().filter(s -> "WARN".equals(s.getStatus())).count();
        metrics.put("failedStages", blockingFails);
        metrics.put("blockingStages", blockingFails);
        metrics.put("warningStages", warnStages);
        metrics.put("secrets", intVal(summary.get("secrets")));

        if (!sonarFlat.isEmpty()) {
            Map<String, Object> sonarMetrics = new LinkedHashMap<>();
            sonarMetrics.put("bugs", intVal(sonarFlat.get("bugs")));
            sonarMetrics.put("vulnerabilities", intVal(sonarFlat.get("vulnerabilities")));
            sonarMetrics.put("codeSmells", intVal(sonarFlat.get("code_smells")));
            sonarMetrics.put("openIssues", intVal(sonarFlat.get("open_issues")));
            sonarMetrics.put("coverage", doubleVal(sonarFlat.get("coverage")));
            sonarMetrics.put("duplications", doubleVal(sonarFlat.get("duplicated_lines_density")));
            sonarMetrics.put("hotspots", intVal(sonarFlat.get("security_hotspots")));
            sonarMetrics.put("ncloc", intVal(sonarFlat.get("ncloc")));

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

    private SonarAvailabilityDto buildSonarAvailability(Map<String, Object> sonar, Application app) {
        String projectKey = sonar.get("sonar_project_key") != null
                ? stringVal(sonar.get("sonar_project_key"))
                : SonarProjectKeyUtil.deriveSonarProjectKey(app.getGitRepositoryUrl());
        boolean available = Boolean.TRUE.equals(sonar.get("sonar_available"));
        String requested = stringVal(sonar.get("requested_branch"));
        String resolved = stringVal(sonar.get("branch"));
        String message = stringVal(sonar.get("branch_fallback_message"));
        if (!available && isBlankStr(message)) {
            message = "SonarQube indisponible — données DefectDojo et CI affichées seules.";
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
                .available(available)
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
        if (ratingRaw == null) {
            ratingRaw = switch (dimension) {
                case "SECURITY" -> sonarFlat.get("security_rating");
                case "RELIABILITY" -> sonarFlat.get("reliability_rating");
                default -> sonarFlat.get("sqale_rating");
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
            Map<String, Object> storedGate
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
                .sonarAvailable(Boolean.TRUE.equals(sonar.get("sonar_available")))
                .build();
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

    private VerdictResolution resolveVerdictWithSource(
            String ciVerdict,
            SecurityScoreDto securityScore,
            List<QualityGateStageDto> stages,
            Map<String, Object> summary
    ) {
        if (ciVerdict != null) {
            return new VerdictResolution(ciVerdict, "CI");
        }
        if (securityScore != null && securityScore.getDerivedVerdict() != null) {
            return new VerdictResolution(securityScore.getDerivedVerdict(), "SCORE");
        }
        boolean blocking = stages.stream().anyMatch(s -> s.isBlocking() && "FAIL".equals(s.getStatus()));
        if (blocking || intVal(summary.get("secrets")) > 0) {
            return new VerdictResolution("NOT_RECOMMENDED", "MERGED");
        }
        if (stages.stream().anyMatch(s -> "WARN".equals(s.getStatus()))) {
            return new VerdictResolution("WITH_WARNINGS", "MERGED");
        }
        return new VerdictResolution("RECOMMENDED", "MERGED");
    }

    private List<String> buildVerdictExplanation(
            List<QualityGateStageDto> stages,
            Map<String, Object> summary,
            Map<String, Integer> bySeverity,
            String verdict,
            Map<String, Object> sonarFlat,
            SecurityScoreDto securityScore
    ) {
        List<String> lines = new ArrayList<>();
        List<QualityGateStageDto> blocking = stages.stream()
                .filter(s -> s.isBlocking() && "FAIL".equals(s.getStatus()))
                .toList();

        if (!blocking.isEmpty()) {
            lines.add("Votre pipeline a " + blocking.size() + " violation(s) bloquante(s) :");
            for (QualityGateStageDto s : blocking) {
                lines.add("• " + s.getToolLabel() + " → " + s.getMessage());
            }
        } else if ("NOT_RECOMMENDED".equals(verdict)) {
            lines.add("Le déploiement est bloqué par le verdict CI security-validation.");
        }

        int highTotal = bySeverity.getOrDefault("high", 0);
        int medTotal = bySeverity.getOrDefault("medium", 0);
        if (highTotal > 0 || medTotal > 0) {
            lines.add(String.format(
                    "Vous avez %d vulnérabilité(s) élevée(s) et %d moyenne(s) au total — elles contribuent à l'alerte même si chaque seuil outil n'est pas dépassé individuellement.",
                    highTotal, medTotal));
        }

        long warns = stages.stream().filter(s -> "WARN".equals(s.getStatus())).count();
        if (warns > 0) {
            lines.add(warns + " étape(s) en avertissement (seuils intermédiaires ou findings non bloquants).");
        }

        if (securityScore != null) {
            lines.add(String.format(
                    "Score de posture : %d/100 (note %s) — pénalités basées sur DefectDojo uniquement ; SonarQube contribue via ratings et Quality Gate.",
                    securityScore.getScore(), securityScore.getGrade()));
        }

        String qgStatus = stringVal(sonarFlat.get("quality_gate_status"));
        if ("OK".equalsIgnoreCase(qgStatus) && securityScore != null && securityScore.getScore() < 75) {
            lines.add("Quality Gate Sonar OK mais score global < 75 — des findings DefectDojo ou des ratings Sonar pénalisent la posture.");
        }

        if (lines.isEmpty()) {
            if ("RECOMMENDED".equals(verdict)) {
                lines.add("Tous les seuils bloquants sont respectés — aucune violation critique détectée.");
            } else {
                lines.add("Analyse basée sur DefectDojo, le dernier summary CI et SonarQube.");
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
            advice.add(n++ + ". Corriger " + s.getToolLabel() + " : " + s.getMessage());
        }

        int secrets = intVal(summary.get("secrets"));
        if (secrets > 0) {
            advice.add(n++ + ". Révoquer les secrets exposés (" + secrets + ") et purger l'historique Git.");
        }

        for (QualityGateToolMetricDto t : tools) {
            if (t.getCritical() <= 0 && t.getHigh() <= 0) continue;
            if ("sonarqube".equals(t.getId()) && t.getHigh() > 0) {
                advice.add(n++ + ". SonarQube : traiter " + t.getHigh() + " vulnérabilité(s) et " + t.getMedium() + " bug(s) signalés.");
            } else if (t.getCritical() > 0 || t.getHigh() > 0) {
                advice.add(n++ + ". " + t.getLabel() + " : réduire les findings (" + t.getCritical() + " critiques, " + t.getHigh() + " élevées).");
            }
        }

        if (advice.isEmpty()) {
            if ("RECOMMENDED".equals(verdict)) {
                advice.add("1. Aucune action bloquante — vous pouvez déployer cette version en environnement éphémère.");
            } else if ("WITH_WARNINGS".equals(verdict)) {
                advice.add("1. Déploiement possible avec surveillance ; planifiez les corrections avant la production.");
            } else {
                advice.add("1. Ne pas déployer tant que les étapes bloquantes ne sont pas corrigées et le pipeline repassé au vert.");
            }
        }
        return advice;
    }

    private String buildScoringNote() {
        return "Score de posture 0–100 (note A–E) : pénalités de sévérité uniquement depuis DefectDojo "
                + "(Critical −8, High −3, Medium −1, Low −0,25) — les vulnérabilités SonarQube ne sont pas re-comptées "
                + "pour éviter le double comptage avec Semgrep/Trivy. SonarQube contribue via ratings Security/Reliability, "
                + "Quality Gate ERROR (plafond 60), couverture et hotspots. "
                + "Seuils CI : SCA critique ≤ " + QualityGateThresholds.SCA_CRITICAL
                + ", container critique ≤ " + QualityGateThresholds.CONTAINER_CRITICAL
                + " (lus depuis summary.json si ingéré). "
                + "Le verdict security-validation reste prioritaire sur le score quand il est disponible.";
    }

    private String buildSummaryText(
            String verdict,
            Map<String, Integer> bySeverity,
            List<QualityGateStageDto> stages,
            SecurityScoreDto securityScore
    ) {
        int total = bySeverity.values().stream().mapToInt(Integer::intValue).sum();
        long blocking = stages.stream().filter(s -> s.isBlocking() && "FAIL".equals(s.getStatus())).count();
        long warn = stages.stream().filter(s -> "WARN".equals(s.getStatus())).count();
        int crit = bySeverity.getOrDefault("critical", 0);
        int high = bySeverity.getOrDefault("high", 0);
        int med = bySeverity.getOrDefault("medium", 0);

        String verdictFr = switch (verdict) {
            case "RECOMMENDED" -> "RECOMMANDÉ";
            case "WITH_WARNINGS" -> "AVEC AVERTISSEMENTS";
            case "NOT_RECOMMENDED" -> "NON RECOMMANDÉ";
            default -> "INCONNU";
        };

        String deployLine = "NOT_RECOMMENDED".equals(verdict) ? " — DÉPLOIEMENT BLOQUÉ" : "";
        String scorePart = securityScore != null
                ? String.format(" · Score %d/100 (%s)", securityScore.getScore(), securityScore.getGrade())
                : "";
        return String.format(
                "%s%s%s — %d vulnérabilité(s) ouvertes · %d critiques · %d élevées · %d moyennes — ❌ %d stage(s) bloquant(s) · ⚠️ %d avertissement(s)",
                verdictFr, deployLine, scorePart, total, crit, high, med, blocking, warn
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
