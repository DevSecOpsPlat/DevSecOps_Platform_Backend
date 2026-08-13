package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.controller.appmgmt.ManagedAppScanRequest;
import com.backend.devsecopsplatform_backend.controller.appmgmt.SecurityPostureResponse;
import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.PipelineStatus;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatch;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatchStatus;
import com.backend.devsecopsplatform_backend.repository.ManagedApplicationRepository;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.repository.appmgmt.ScanBatchRepository;
import com.backend.devsecopsplatform_backend.service.EncryptionService;
import com.backend.devsecopsplatform_backend.service.GitHubValidationService;
import com.backend.devsecopsplatform_backend.service.GitLabService;
import com.backend.devsecopsplatform_backend.service.appmgmt.ScanBatchWriteService.PreparedScan;
import com.backend.devsecopsplatform_backend.service.appmgmt.dto.ScanBatchStateDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.gitlab4j.api.models.Pipeline;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Orchestration scan application (lot) — Chantier 2.
 * <p>Pas de {@code @Transactional} sur {@link #scanApplication} : crée/commit via
 * {@link ScanBatchWriteService}, déclenche GitLab hors tx, puis 2ᵉ écriture.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class ManagedAppScanService {

    private final ManagedApplicationRepository appRepository;
    private final ScanBatchRepository scanBatchRepository;
    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final UserRepository userRepository;
    private final ScanBatchStateService scanBatchStateService;
    private final ScanBatchCompletionService scanBatchCompletionService;
    private final ScanBatchWriteService scanBatchWriteService;
    private final GitLabService gitLabService;
    private final GitHubValidationService gitHubValidationService;
    private final EncryptionService encryptionService;

    @Value("${scan.posture.head-check-ttl-ms:300000}")
    private long headCheckTtlMs;

    /**
     * Orchestrateur non transactionnel :
     * <ol>
     *   <li>tx1 — {@link ScanBatchWriteService#createPendingBatch} (commit)</li>
     *   <li>hors tx — trigger GitLab ; échec → {@code markBatchFailedTechnical}</li>
     *   <li>tx2 — {@link ScanBatchWriteService#attachGitlabPipeline}</li>
     * </ol>
     */
    public ScanBatchStateDto scanApplication(UUID appId, ManagedAppScanRequest request) {
        User user = currentUser();
        ManagedApplication app = appRepository.findByIdAndCreatedBy(appId, user)
                .orElseThrow(() -> new AppValidationException("Application introuvable ou accès refusé."));

        List<AppService> selected = resolveServices(app, request);
        if (selected.isEmpty()) {
            throw new AppValidationException("Aucun service à scanner.");
        }

        List<ScanBatch> open = scanBatchRepository.findByAppIdAndStatusIn(
                app.getId(),
                List.of(ScanBatchStatus.PENDING, ScanBatchStatus.RUNNING));
        if (!open.isEmpty()) {
            throw new AppValidationException(
                    "Un scan est déjà en cours pour cette application (lot "
                            + open.get(0).getId() + "). Attends sa fin avant d'en lancer un autre.");
        }

        Map<UUID, String> branchByService = resolveBranches(selected, request);

        Map<UUID, String> commitByService = new LinkedHashMap<>();
        Map<UUID, String> tokenByService = new LinkedHashMap<>();
        for (AppService svc : selected) {
            String token = resolveToken(svc);
            tokenByService.put(svc.getId(), token);
            commitByService.put(svc.getId(), gitHubValidationService.resolveCommitSha(
                    svc.getGitRepositoryUrl(), branchByService.get(svc.getId()), token));
        }

        // tx1 — commit avant GitLab (proxy ScanBatchWriteService)
        PreparedScan prepared = scanBatchWriteService.createPendingBatch(
                app, user, selected, branchByService, commitByService, tokenByService);

        Map<String, String> variables = buildPipelineVariables(
                app, selected, branchByService, prepared, tokenByService);

        Pipeline pipeline;
        try {
            pipeline = gitLabService.triggerCiPipeline(variables);
        } catch (Exception e) {
            // Lot déjà commité → REQUIRES_NEW le voit
            scanBatchCompletionService.markBatchFailedTechnical(
                    prepared.batchId(), "Déclenchement GitLab impossible: " + e.getMessage());
            throw new AppValidationException("Déclenchement GitLab impossible: " + e.getMessage());
        }

        Long pipelineId = pipeline.getId();
        PipelineStatus st = PipelineStatus.fromGitLabStatus(
                pipeline.getStatus() != null ? pipeline.getStatus().toString() : "running");

        // tx2
        scanBatchWriteService.attachGitlabPipeline(
                prepared.batchId(), prepared.executionIds(), pipelineId, st);

        log.info("🔎 Scan lot {} — app={} services={} pipeline=#{}",
                prepared.batchId(), app.getId(), selected.size(), pipelineId);

        return scanBatchStateService.getState(prepared.batchId())
                .orElseThrow(() -> new AppValidationException("Lot introuvable après création."));
    }

    private Map<String, String> buildPipelineVariables(
            ManagedApplication app,
            List<AppService> selected,
            Map<UUID, String> branchByService,
            PreparedScan prepared,
            Map<UUID, String> tokenByService
    ) {
        Map<String, String> variables = new LinkedHashMap<>();
        variables.put("ACTION", "scan");
        variables.put("SCAN_BATCH_ID", prepared.batchId().toString());
        variables.put("APP_ID", app.getId().toString());
        variables.put("APP_SLUG", app.getSlug());
        variables.put("SERVICES_JSON", prepared.servicesJson());
        // Compat mono uniquement si 1 service — sinon le CI doit lire SERVICES_JSON (pas de fallback 1er repo).
        if (selected.size() == 1) {
            AppService only = selected.get(0);
            String branch = branchByService.get(only.getId());
            String token = tokenByService.getOrDefault(only.getId(), "");
            variables.put("GIT_REPO_URL", only.getGitRepositoryUrl());
            variables.put("GIT_BRANCH", branch != null ? branch : "main");
            variables.put("GITHUB_TOKEN", token != null ? token : "");
            variables.put("APPLICATION_ID", only.getId().toString());
            variables.put("DOCKERFILE_PATH",
                    only.getDockerfilePath() != null ? only.getDockerfilePath() : "./Dockerfile");
        } else {
            log.info("Scan lot multi-services: {} services, SERVICES_JSON length={}, batchId={}",
                    selected.size(),
                    prepared.servicesJson() != null ? prepared.servicesJson().length() : 0,
                    prepared.batchId());
        }
        return variables;
    }

    public ScanBatchStateDto scanSingleManagedService(AppService svc, String branchOverride) {
        ManagedApplication app = svc.getManagedApplication();
        if (app == null || app.getId() == null) {
            throw new AppValidationException(
                    "Ce service n'est rattaché à aucune application managée — scan lot impossible.");
        }
        ManagedAppScanRequest req = new ManagedAppScanRequest();
        req.setServiceIds(List.of(svc.getId()));
        if (branchOverride != null && !branchOverride.isBlank()) {
            req.setBranch(branchOverride.trim());
        }
        return scanApplication(app.getId(), req);
    }

    @Transactional(readOnly = true)
    public List<ScanBatchStateDto> listBatches(UUID appId) {
        User user = currentUser();
        ManagedApplication app = appRepository.findByIdAndCreatedBy(appId, user)
                .orElseThrow(() -> new AppValidationException("Application introuvable ou accès refusé."));
        List<ScanBatch> batches = scanBatchRepository.findByManagedApplicationIdOrderByCreatedAtDesc(
                app.getId(), PageRequest.of(0, 50));
        return scanBatchStateService.getStates(batches);
    }

    @Transactional(readOnly = true)
    public ScanBatchStateDto getBatch(UUID appId, UUID batchId) {
        User user = currentUser();
        appRepository.findByIdAndCreatedBy(appId, user)
                .orElseThrow(() -> new AppValidationException("Application introuvable ou accès refusé."));
        return scanBatchStateService.getStateForApp(appId, batchId)
                .orElseThrow(() -> new AppValidationException("Lot de scan introuvable."));
    }

    /**
     * Posture : dernier COMPLETE si dispo ; sinon dernier lot terminal (PARTIAL/FAILED)
     * pour ne pas afficher « aucun scan » après un lot partiel.
     */
    public SecurityPostureResponse securityPosture(UUID appId) {
        User user = currentUser();
        ManagedApplication app = appRepository.findByIdAndCreatedBy(appId, user)
                .orElseThrow(() -> new AppValidationException("Application introuvable ou accès refusé."));

        List<ScanBatch> complete = scanBatchRepository.findLatestCompleteByAppId(appId, PageRequest.of(0, 1));
        ScanBatch batch = null;
        boolean isComplete = false;
        if (!complete.isEmpty()) {
            batch = complete.get(0);
            isComplete = true;
        } else {
            List<ScanBatch> latest = scanBatchRepository.findByManagedApplicationIdOrderByCreatedAtDesc(
                    appId, PageRequest.of(0, 1));
            if (!latest.isEmpty()) {
                ScanBatch candidate = latest.get(0);
                ScanBatchStatus st = candidate.getStatus();
                if (st == ScanBatchStatus.PARTIAL || st == ScanBatchStatus.FAILED
                        || st == ScanBatchStatus.COMPLETE) {
                    batch = candidate;
                    isComplete = st == ScanBatchStatus.COMPLETE;
                } else if (st == ScanBatchStatus.PENDING || st == ScanBatchStatus.RUNNING) {
                    return SecurityPostureResponse.builder()
                            .managedApplicationId(appId)
                            .hasCompleteBatch(false)
                            .batchStatus(st.name())
                            .batchId(candidate.getId())
                            .gitlabPipelineId(candidate.getGitlabPipelineId())
                            .expectedServiceCount(candidate.getExpectedServiceCount())
                            .finishedServiceCount(0)
                            .obsolete(false)
                            .obsoleteServices(List.of())
                            .message("Scan en cours — verdict disponible à la fin du lot.")
                            .build();
                }
            }
        }

        if (batch == null) {
            return SecurityPostureResponse.builder()
                    .managedApplicationId(appId)
                    .hasCompleteBatch(false)
                    .obsolete(false)
                    .obsoleteServices(List.of())
                    .message("Aucun lot — lance un scan pour obtenir un verdict.")
                    .build();
        }

        ScanBatchStateDto state = scanBatchStateService.getState(batch.getId()).orElse(null);
        List<PipelineExecution> executions =
                pipelineExecutionRepository.findByScanBatchIdWithService(batch.getId());

        refreshHeadCacheIfStale(executions);

        executions = pipelineExecutionRepository.findByScanBatchIdWithService(batch.getId());
        List<SecurityPostureResponse.ObsoleteService> obsolete = new ArrayList<>();
        for (PipelineExecution pe : executions) {
            AppService svc = pe.getAppService();
            if (svc == null || pe.getCommitSha() == null || pe.getCommitSha().isBlank()) {
                continue;
            }
            String head = pe.getCheckedHeadSha();
            if (head != null && !head.equalsIgnoreCase(pe.getCommitSha())) {
                obsolete.add(SecurityPostureResponse.ObsoleteService.builder()
                        .serviceId(svc.getId())
                        .serviceName(svc.getName())
                        .gitBranch(pe.getGitBranch())
                        .scannedCommitSha(pe.getCommitSha())
                        .headCommitSha(head)
                        .build());
            }
        }

        String statusName = batch.getStatus() != null ? batch.getStatus().name() : null;
        String message;
        if (isComplete) {
            message = obsolete.isEmpty()
                    ? "Verdict du dernier lot COMPLETE."
                    : "Verdict obsolète : au moins un service a avancé sur HEAD.";
        } else if (batch.getStatus() == ScanBatchStatus.PARTIAL) {
            int fin = state != null ? state.finishedServiceCount() : 0;
            int exp = batch.getExpectedServiceCount();
            message = "Scan partiel (" + fin + "/" + exp
                    + ") — tous les services n'ont pas été scannés dans le pipeline.";
        } else if (batch.getStatus() == ScanBatchStatus.FAILED) {
            message = "Dernier lot en échec — relance un scan.";
        } else {
            message = "Dernier lot : " + statusName;
        }

        return SecurityPostureResponse.builder()
                .managedApplicationId(app.getId())
                .hasCompleteBatch(isComplete)
                .batchStatus(statusName)
                .batchId(batch.getId())
                .batchFinishedAt(batch.getFinishedAt())
                .batchCreatedAt(batch.getCreatedAt())
                .verdict(batch.getVerdict())
                .securityScore(batch.getSecurityScore())
                .grade(batch.getGrade())
                .gitlabPipelineId(batch.getGitlabPipelineId())
                .expectedServiceCount(batch.getExpectedServiceCount())
                .finishedServiceCount(state != null ? state.finishedServiceCount() : 0)
                .obsolete(!obsolete.isEmpty())
                .obsoleteServices(obsolete)
                .bySeverity(extractAggregatedSeverity(batch, executions))
                .topBlockingFindings(extractTopBlockingFindings(batch, executions))
                .dimensioningService(extractDimensioningService(batch))
                .services(extractServiceSummaries(batch, executions))
                .qualityGates(extractQualityGates(batch, executions))
                .message(message)
                .build();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Integer> extractAggregatedSeverity(ScanBatch batch, List<PipelineExecution> executions) {
        Map<String, Object> payload = batch.getVerdictPayloadJson();
        if (payload != null && payload.get("aggregatedBySeverity") instanceof Map<?, ?> m) {
            Map<String, Integer> out = new LinkedHashMap<>();
            for (String k : List.of("critical", "high", "medium", "low", "info")) {
                Object v = m.get(k);
                out.put(k, v instanceof Number n ? n.intValue() : 0);
            }
            return out;
        }
        Map<String, Object> rollup = new LinkedHashMap<>();
        ScanBatchAggregationService.attachDefectDojoAppRollup(executions, rollup);
        Object agg = rollup.get("aggregatedBySeverity");
        if (agg instanceof Map<?, ?> m) {
            Map<String, Integer> out = new LinkedHashMap<>();
            m.forEach((k, v) -> out.put(String.valueOf(k), v instanceof Number n ? n.intValue() : 0));
            return out;
        }
        return Map.of("critical", 0, "high", 0, "medium", 0, "low", 0, "info", 0);
    }

    @SuppressWarnings("unchecked")
    private List<SecurityPostureResponse.TopBlockingFinding> extractTopBlockingFindings(
            ScanBatch batch, List<PipelineExecution> executions
    ) {
        List<?> raw = null;
        Map<String, Object> payload = batch.getVerdictPayloadJson();
        if (payload != null && payload.get("topBlockingFindings") instanceof List<?> list) {
            raw = list;
        } else {
            Map<String, Object> rollup = new LinkedHashMap<>();
            ScanBatchAggregationService.attachDefectDojoAppRollup(executions, rollup);
            if (rollup.get("topBlockingFindings") instanceof List<?> list) {
                raw = list;
            }
        }
        if (raw == null) {
            return List.of();
        }
        List<SecurityPostureResponse.TopBlockingFinding> out = new ArrayList<>();
        for (Object o : raw) {
            if (!(o instanceof Map<?, ?> m)) {
                continue;
            }
            Object fid = m.get("findingId");
            Object sid = m.get("serviceId");
            UUID serviceId = null;
            if (sid != null && !String.valueOf(sid).isBlank()) {
                try {
                    serviceId = UUID.fromString(String.valueOf(sid));
                } catch (IllegalArgumentException ignored) {
                    serviceId = null;
                }
            }
            out.add(SecurityPostureResponse.TopBlockingFinding.builder()
                    .findingId(fid instanceof Number n ? n.intValue() : null)
                    .title(m.get("title") != null ? String.valueOf(m.get("title")) : null)
                    .severity(m.get("severity") != null ? String.valueOf(m.get("severity")) : null)
                    .serviceId(serviceId)
                    .serviceName(m.get("serviceName") != null ? String.valueOf(m.get("serviceName")) : null)
                    .scanType(m.get("scanType") != null ? String.valueOf(m.get("scanType")) : null)
                    .filePath(m.get("filePath") != null ? String.valueOf(m.get("filePath")) : null)
                    .cve(m.get("cve") != null ? String.valueOf(m.get("cve")) : null)
                    .build());
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private SecurityPostureResponse.DimensioningService extractDimensioningService(ScanBatch batch) {
        Map<String, Object> payload = batch.getVerdictPayloadJson();
        if (payload == null || !(payload.get("dimensioningService") instanceof Map<?, ?> m)) {
            return null;
        }
        UUID serviceId = null;
        Object sid = m.get("serviceId");
        if (sid != null && !String.valueOf(sid).isBlank()) {
            try {
                serviceId = UUID.fromString(String.valueOf(sid));
            } catch (IllegalArgumentException ignored) {
                serviceId = null;
            }
        }
        Object score = m.get("securityScore");
        Object adj = m.get("adjustedScoreForSelection");
        return SecurityPostureResponse.DimensioningService.builder()
                .serviceId(serviceId)
                .serviceName(m.get("serviceName") != null ? String.valueOf(m.get("serviceName")) : null)
                .serviceRole(m.get("serviceRole") != null ? String.valueOf(m.get("serviceRole")) : null)
                .publiclyExposed(m.get("publiclyExposed") instanceof Boolean b ? b : null)
                .securityScore(score instanceof Number n ? n.intValue() : null)
                .grade(m.get("grade") != null ? String.valueOf(m.get("grade")) : null)
                .adjustedScoreForSelection(adj instanceof Number n ? n.intValue() : null)
                .build();
    }

    @SuppressWarnings("unchecked")
    private List<SecurityPostureResponse.ServiceSummary> extractServiceSummaries(
            ScanBatch batch, List<PipelineExecution> executions
    ) {
        Map<String, Object> payload = batch.getVerdictPayloadJson();
        Map<String, Map<String, Object>> byServiceId = new LinkedHashMap<>();
        if (payload != null && payload.get("services") instanceof List<?> list) {
            for (Object o : list) {
                if (o instanceof Map<?, ?> m && m.get("serviceId") != null) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    m.forEach((k, v) -> row.put(String.valueOf(k), v));
                    byServiceId.put(String.valueOf(m.get("serviceId")), row);
                }
            }
        }
        List<SecurityPostureResponse.ServiceSummary> out = new ArrayList<>();
        for (PipelineExecution pe : executions) {
            AppService svc = pe.getAppService();
            if (svc == null || svc.getId() == null) {
                continue;
            }
            Map<String, Object> row = byServiceId.getOrDefault(svc.getId().toString(), Map.of());
            Object score = row.get("securityScore");
            out.add(SecurityPostureResponse.ServiceSummary.builder()
                    .serviceId(svc.getId())
                    .serviceName(svc.getName())
                    .serviceRole(row.get("serviceRole") != null
                            ? String.valueOf(row.get("serviceRole"))
                            : (svc.getRole() != null ? svc.getRole().name() : null))
                    .verdict(row.get("verdict") != null ? String.valueOf(row.get("verdict")) : null)
                    .securityScore(score instanceof Number n ? n.intValue() : null)
                    .grade(row.get("grade") != null ? String.valueOf(row.get("grade")) : null)
                    .bySeverity(ScanBatchAggregationService.resolveDdBySeverity(
                            pe.getQualityGateJson() != null ? pe.getQualityGateJson() : Map.of()))
                    .hardGateViolated(row.get("hardGateViolated") instanceof Boolean b ? b : null)
                    .indeterminate(row.get("indeterminate") instanceof Boolean b ? b : null)
                    .hardGateIds(asStringList(row.get("hardGateIds")))
                    .indeterminateSources(asStringList(row.get("indeterminateSources")))
                    .build());
        }
        return out;
    }

    private static List<String> asStringList(Object raw) {
        if (!(raw instanceof List<?> list) || list.isEmpty()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (Object o : list) {
            if (o != null) {
                out.add(String.valueOf(o));
            }
        }
        return out;
    }

    /**
     * Checklist quality gate app : agrège les hard gates des services + contexte Sonar.
     * Sonar indisponible → UNKNOWN (pas FAIL) ; Critical DefectDojo → FAIL.
     */
    private List<SecurityPostureResponse.QualityGateItem> extractQualityGates(
            ScanBatch batch, List<PipelineExecution> executions
    ) {
        Map<String, Object> payload = batch.getVerdictPayloadJson();
        Map<String, Integer> sev = extractAggregatedSeverity(batch, executions);
        int critical = sev.getOrDefault("critical", 0);
        int high = sev.getOrDefault("high", 0);

        Set<String> failedIds = new LinkedHashSet<>();
        Set<String> unknownSources = new LinkedHashSet<>();
        List<String> failedServices = new ArrayList<>();
        if (payload != null && payload.get("services") instanceof List<?> list) {
            for (Object o : list) {
                if (!(o instanceof Map<?, ?> m)) continue;
                String svcName = m.get("serviceName") != null ? String.valueOf(m.get("serviceName")) : null;
                if (Boolean.TRUE.equals(m.get("hardGateViolated"))) {
                    if (svcName != null && !failedServices.contains(svcName)) {
                        failedServices.add(svcName);
                    }
                    Object ids = m.get("hardGateIds");
                    if (ids instanceof List<?> idList) {
                        idList.forEach(id -> {
                            if (id != null) failedIds.add(String.valueOf(id));
                        });
                    }
                }
                Object src = m.get("indeterminateSources");
                if (src instanceof List<?> srcList) {
                    srcList.forEach(s -> {
                        if (s != null) unknownSources.add(String.valueOf(s));
                    });
                }
            }
        }

        boolean anySonarAvailable = false;
        int secretsTotal = 0;
        boolean secretsKnown = false;
        for (PipelineExecution pe : executions) {
            Map<String, Object> gate = pe.getQualityGateJson() != null ? pe.getQualityGateJson() : Map.of();
            if (ScanBatchAggregationService.isSonarAvailableFromGate(gate)) {
                anySonarAvailable = true;
            }
            if (gate.containsKey("secrets")) {
                secretsKnown = true;
                Object s = gate.get("secrets");
                if (s instanceof Number n) secretsTotal += n.intValue();
            }
        }

        List<SecurityPostureResponse.QualityGateItem> items = new ArrayList<>();

        // Critical DefectDojo — vrai hard gate de blocage
        if (critical > 0 || failedIds.contains("dd_critical")) {
            items.add(SecurityPostureResponse.QualityGateItem.builder()
                    .id("dd_critical")
                    .label("Vulnérabilités critiques (DefectDojo)")
                    .status("FAIL")
                    .message(critical + " Critical open — hard gate (tolérance zéro). "
                            + "Ce n'est pas lié à SonarQube.")
                    .scope(failedServices.isEmpty() ? "application" : String.join(", ", failedServices))
                    .build());
        } else {
            items.add(SecurityPostureResponse.QualityGateItem.builder()
                    .id("dd_critical")
                    .label("Vulnérabilités critiques (DefectDojo)")
                    .status("PASS")
                    .message("Aucun Critical open sur le rollup app.")
                    .scope("application")
                    .build());
        }

        // Secrets
        if (!secretsKnown || unknownSources.stream().anyMatch(s -> s.toLowerCase().contains("secret"))) {
            items.add(SecurityPostureResponse.QualityGateItem.builder()
                    .id("secrets")
                    .label("Secrets exposés (Gitleaks)")
                    .status(failedIds.contains("secrets") ? "FAIL" : "UNKNOWN")
                    .message(failedIds.contains("secrets")
                            ? secretsTotal + " secret(s) — hard gate"
                            : "Scan secrets non évalué / incomplet sur au moins un service")
                    .scope("application")
                    .build());
        } else if (secretsTotal > 0 || failedIds.contains("secrets")) {
            items.add(SecurityPostureResponse.QualityGateItem.builder()
                    .id("secrets")
                    .label("Secrets exposés (Gitleaks)")
                    .status("FAIL")
                    .message(secretsTotal + " secret(s) exposé(s)")
                    .scope("application")
                    .build());
        } else {
            items.add(SecurityPostureResponse.QualityGateItem.builder()
                    .id("secrets")
                    .label("Secrets exposés (Gitleaks)")
                    .status("PASS")
                    .message("Aucun secret détecté")
                    .scope("application")
                    .build());
        }

        // Sonar — indisponible = UNKNOWN, pas FAIL
        boolean sonarUnknown = !anySonarAvailable
                || unknownSources.stream().anyMatch(s -> s.toLowerCase().contains("sonar"));
        if (failedIds.contains("sonar_blocker") || failedIds.contains("sonar_qg")) {
            items.add(SecurityPostureResponse.QualityGateItem.builder()
                    .id("sonar")
                    .label("Quality Gate SonarQube")
                    .status("FAIL")
                    .message("Blocker ou Quality Gate ERROR sur au moins un service")
                    .scope("application")
                    .build());
        } else if (sonarUnknown) {
            items.add(SecurityPostureResponse.QualityGateItem.builder()
                    .id("sonar")
                    .label("Quality Gate SonarQube")
                    .status("UNKNOWN")
                    .message("SonarQube non disponible ou job échoué — n'entraîne pas seul un « bloqué ». "
                            + "Le verdict devient INCOMPLET si aucun autre hard gate.")
                    .scope("application")
                    .build());
        } else {
            items.add(SecurityPostureResponse.QualityGateItem.builder()
                    .id("sonar")
                    .label("Quality Gate SonarQube")
                    .status("PASS")
                    .message("Pas de Blocker / QG ERROR signalé")
                    .scope("application")
                    .build());
        }

        // High informatif
        items.add(SecurityPostureResponse.QualityGateItem.builder()
                .id("dd_high")
                .label("Vulnérabilités High (DefectDojo)")
                .status(high > 0 ? "WARN" : "PASS")
                .message(high > 0
                        ? high + " High open — n'est pas un hard gate seul, mais pèse sur le score"
                        : "Aucun High open")
                .scope("application")
                .build());

        return items;
    }

    private void refreshHeadCacheIfStale(List<PipelineExecution> executions) {
        LocalDateTime cutoff = LocalDateTime.now().minus(Duration.ofMillis(Math.max(headCheckTtlMs, 30_000)));
        for (PipelineExecution pe : executions) {
            if (pe.getHeadCheckedAt() != null && pe.getHeadCheckedAt().isAfter(cutoff)) {
                continue; // cache frais — pas d'appel GitHub
            }
            AppService svc = pe.getAppService();
            if (svc == null) {
                continue;
            }
            String token = resolveToken(svc);
            String head = gitHubValidationService.resolveCommitSha(
                    svc.getGitRepositoryUrl(), pe.getGitBranch(), token);
            // Échec réseau : ne pas écraser un SHA valide ; avancer headCheckedAt pour éviter le hammering
            scanBatchWriteService.updateHeadCache(pe.getId(), head);
        }
    }

    private List<AppService> resolveServices(ManagedApplication app, ManagedAppScanRequest request) {
        List<AppService> all = app.getServices() != null ? app.getServices() : List.of();
        if (request == null || request.getServiceIds() == null || request.getServiceIds().isEmpty()) {
            return new ArrayList<>(all);
        }
        var wanted = request.getServiceIds().stream().collect(Collectors.toSet());
        List<AppService> selected = all.stream().filter(s -> wanted.contains(s.getId())).toList();
        if (selected.size() != wanted.size()) {
            throw new AppValidationException("Un ou plusieurs serviceIds n'appartiennent pas à cette application.");
        }
        return new ArrayList<>(selected);
    }

    private Map<UUID, String> resolveBranches(List<AppService> services, ManagedAppScanRequest request) {
        Map<UUID, String> out = new LinkedHashMap<>();
        String global = request != null && request.getBranch() != null && !request.getBranch().isBlank()
                ? request.getBranch().trim() : null;
        Map<UUID, String> per = request != null && request.getBranchesByServiceId() != null
                ? request.getBranchesByServiceId() : Map.of();
        for (AppService svc : services) {
            String b = per.get(svc.getId());
            if (b == null || b.isBlank()) {
                b = global;
            }
            if (b == null || b.isBlank()) {
                b = svc.getGitBranch() != null && !svc.getGitBranch().isBlank() ? svc.getGitBranch() : "main";
            }
            out.put(svc.getId(), b.trim());
        }
        return out;
    }

    private String resolveToken(AppService svc) {
        if (svc.getGitToken() != null && !svc.getGitToken().isBlank()) {
            return svc.getGitToken();
        }
        if (svc.getEncryptedGithubToken() != null && !svc.getEncryptedGithubToken().isBlank()) {
            try {
                return encryptionService.decrypt(svc.getEncryptedGithubToken());
            } catch (Exception e) {
                log.warn("Impossible de déchiffrer encryptedGithubToken du service {}: {}",
                        svc.getId(), e.getMessage());
            }
        }
        return "";
    }

    private User currentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getName() == null) {
            throw new AppValidationException("Utilisateur non authentifié.");
        }
        return userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new AppValidationException("Utilisateur non trouvé."));
    }
}
