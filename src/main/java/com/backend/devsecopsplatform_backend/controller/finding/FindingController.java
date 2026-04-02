package com.backend.devsecopsplatform_backend.controller.finding;

import com.backend.devsecopsplatform_backend.entity.Finding;
import com.backend.devsecopsplatform_backend.entity.FindingOccurrence;
import com.backend.devsecopsplatform_backend.entity.FindingStatus;
import com.backend.devsecopsplatform_backend.entity.ScanType;
import com.backend.devsecopsplatform_backend.entity.Severity;
import com.backend.devsecopsplatform_backend.entity.Application;
import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.repository.FindingOccurrenceRepository;
import com.backend.devsecopsplatform_backend.repository.FindingRepository;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.service.AiAnalysisService;
import com.backend.devsecopsplatform_backend.service.finding.ProjectStackInference;
import com.backend.devsecopsplatform_backend.service.SourceSnippetFetcherService;
import com.backend.devsecopsplatform_backend.service.finding.FindingIngestionService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/findings")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "http://localhost:4200")
public class FindingController {

    private final FindingRepository findingRepository;
    private final FindingOccurrenceRepository findingOccurrenceRepository;
    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final FindingIngestionService findingIngestionService;
    private final AiAnalysisService aiAnalysisService;
    private final ObjectMapper objectMapper;
    private final SourceSnippetFetcherService sourceSnippetFetcherService;
    private final EphemeralEnvironmentRepository ephemeralEnvironmentRepository;

    /**
     * Détail d'un finding pour le dashboard + remédiation IA (vérifie que le finding est lié à l'env via une occurrence).
     */
    @GetMapping("/detail/{findingId}")
    public ResponseEntity<Map<String, Object>> getDetail(
            @PathVariable UUID findingId,
            @RequestParam(required = false) UUID envId,
            @RequestParam(required = false) UUID appId
    ) {
        UUID effectiveEnvId = envId;
        if (effectiveEnvId != null) {
            if (findingOccurrenceRepository.countByFinding_IdAndPipelineExecution_Environment_Id(findingId, effectiveEnvId) == 0) {
                // Fallback: si la liste vient du scope application (env différent), on accepte via appId.
                effectiveEnvId = null;
            }
        }
        if (effectiveEnvId == null && appId != null) {
            if (findingOccurrenceRepository.countByFindingIdAndApplicationId(findingId, appId) == 0) {
                return ResponseEntity.notFound().build();
            }
            var occs = findingOccurrenceRepository.findByFindingIdAndApplicationIdOrderByObservedAtDesc(findingId, appId);
            if (!occs.isEmpty() && occs.get(0).getPipelineExecution() != null && occs.get(0).getPipelineExecution().getEnvironment() != null) {
                effectiveEnvId = occs.get(0).getPipelineExecution().getEnvironment().getId();
            }
        }
        if (effectiveEnvId == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "envId ou appId requis"));
        }
        Finding f = findingRepository.findById(findingId).orElse(null);
        if (f == null) {
            return ResponseEntity.notFound().build();
        }
        FindingOccurrence occ = findingOccurrenceRepository.findFirstByFinding_IdOrderByObservedAtDesc(findingId).orElse(null);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", f.getId());
        body.put("fingerprint", f.getFingerprint());
        body.put("scanType", f.getScanType() != null ? f.getScanType().name() : null);
        body.put("toolName", f.getToolName());
        body.put("severity", f.getSeverity() != null ? f.getSeverity().name() : null);
        body.put("status", f.getStatus() != null ? f.getStatus().name() : null);
        body.put("ruleId", f.getRuleId());
        body.put("title", f.getTitle());
        body.put("description", f.getDescription());
        body.put("filePath", f.getFilePath());
        body.put("lineStart", f.getLineStart());
        body.put("lineEnd", f.getLineEnd());
        body.put("cve", f.getCve());
        body.put("cwe", f.getCwe());
        body.put("packageName", f.getPackageName());
        body.put("installedVersion", f.getInstalledVersion());
        body.put("fixedVersion", f.getFixedVersion());
        body.put("createdAt", f.getCreatedAt());
        body.put("updatedAt", f.getUpdatedAt());
        if (occ != null) {
            body.put("evidenceJson", occ.getEvidenceJson());
            body.put("lastArtifactPath", occ.getArtifactPath());
            body.put("lastJobName", occ.getJobName());
            body.put("lastObservedAt", occ.getObservedAt());
        }
        body.put("effectiveEnvId", effectiveEnvId);
        var snippetFetch = sourceSnippetFetcherService.tryFetchSnippet(effectiveEnvId, f.getFilePath(), f.getLineStart(), f.getLineEnd());
        if (snippetFetch.isPresent()) {
            body.put("codeSnippet", snippetFetch.get().content());
            body.put("codeContextSource", snippetFetch.get().source());
        } else {
            body.put("codeContextSource", "NONE");
        }
        return ResponseEntity.ok(body);
    }

    /**
     * Remédiation IA pour un finding : petit contexte (pas le ZIP complet) + snippet optionnel.
     * Pour éviter quota cloud : {@code ai.provider=ollama} + Ollama local.
     */
    @PostMapping("/detail/{findingId}/ai-remediation")
    public ResponseEntity<FindingAiRemediationResponse> aiRemediation(
            @PathVariable UUID findingId,
            @RequestParam(required = false) UUID envId,
            @RequestParam(required = false) UUID appId,
            @RequestBody(required = false) FindingAiRemediationRequest request
    ) {
        UUID effectiveEnvId = envId;
        if (effectiveEnvId != null) {
            if (findingOccurrenceRepository.countByFinding_IdAndPipelineExecution_Environment_Id(findingId, effectiveEnvId) == 0) {
                effectiveEnvId = null;
            }
        }
        if (effectiveEnvId == null && appId != null) {
            if (findingOccurrenceRepository.countByFindingIdAndApplicationId(findingId, appId) == 0) {
                return ResponseEntity.notFound().build();
            }
            var occs = findingOccurrenceRepository.findByFindingIdAndApplicationIdOrderByObservedAtDesc(findingId, appId);
            if (!occs.isEmpty() && occs.get(0).getPipelineExecution() != null && occs.get(0).getPipelineExecution().getEnvironment() != null) {
                effectiveEnvId = occs.get(0).getPipelineExecution().getEnvironment().getId();
            }
        }
        if (effectiveEnvId == null) {
            return ResponseEntity.badRequest().build();
        }
        Finding f = findingRepository.findById(findingId).orElse(null);
        if (f == null) {
            return ResponseEntity.notFound().build();
        }
        FindingOccurrence occ = findingOccurrenceRepository.findFirstByFinding_IdOrderByObservedAtDesc(findingId).orElse(null);
        Application app = resolveApplicationForEnv(effectiveEnvId);

        String snippet = "";
        String codeContextSource = "NONE";
        if (request != null && request.getCodeSnippet() != null && !request.getCodeSnippet().isBlank()) {
            snippet = request.getCodeSnippet().strip();
            codeContextSource = "MANUAL";
        } else {
            var fetched = sourceSnippetFetcherService.tryFetchSnippet(effectiveEnvId, f.getFilePath(), f.getLineStart(), f.getLineEnd());
            if (fetched.isPresent()) {
                snippet = fetched.get().content();
                codeContextSource = fetched.get().source();
            }
        }

        String ctx = buildFindingContextForAi(f, occ, app, snippet);
        FindingAiRemediationResponse out = aiAnalysisService.analyzeFindingRemediation(ctx, snippet);
        return ResponseEntity.ok(out.toBuilder().codeContextSource(codeContextSource).build());
    }

    /**
     * Chat pédagogique (questions / confusions) sur le même finding ; historique géré côté client.
     */
    @PostMapping("/detail/{findingId}/ai-chat")
    public ResponseEntity<Map<String, String>> findingChat(
            @PathVariable UUID findingId,
            @RequestParam(required = false) UUID envId,
            @RequestParam(required = false) UUID appId,
            @Valid @RequestBody FindingChatRequest request
    ) {
        UUID effectiveEnvId = envId;
        if (effectiveEnvId != null) {
            if (findingOccurrenceRepository.countByFinding_IdAndPipelineExecution_Environment_Id(findingId, effectiveEnvId) == 0) {
                effectiveEnvId = null;
            }
        }
        if (effectiveEnvId == null && appId != null) {
            if (findingOccurrenceRepository.countByFindingIdAndApplicationId(findingId, appId) == 0) {
                return ResponseEntity.notFound().build();
            }
            var occs = findingOccurrenceRepository.findByFindingIdAndApplicationIdOrderByObservedAtDesc(findingId, appId);
            if (!occs.isEmpty() && occs.get(0).getPipelineExecution() != null && occs.get(0).getPipelineExecution().getEnvironment() != null) {
                effectiveEnvId = occs.get(0).getPipelineExecution().getEnvironment().getId();
            }
        }
        if (effectiveEnvId == null) {
            return ResponseEntity.badRequest().build();
        }
        Finding f = findingRepository.findById(findingId).orElse(null);
        if (f == null) {
            return ResponseEntity.notFound().build();
        }
        FindingOccurrence occ = findingOccurrenceRepository.findFirstByFinding_IdOrderByObservedAtDesc(findingId).orElse(null);
        Application app = resolveApplicationForEnv(effectiveEnvId);

        String snippetBlock = "";
        var chatSnippet = sourceSnippetFetcherService.tryFetchSnippet(effectiveEnvId, f.getFilePath(), f.getLineStart(), f.getLineEnd());
        if (chatSnippet.isPresent()) {
            snippetBlock = chatSnippet.get().content();
        }

        String ctx = buildFindingContextForAi(f, occ, app, snippetBlock);

        List<AiAnalysisService.ChatTurn> turns = request.getMessages().stream()
                .map(m -> new AiAnalysisService.ChatTurn(
                        m.getRole() != null ? m.getRole().strip() : "",
                        m.getContent() != null ? m.getContent() : ""))
                .collect(Collectors.toList());

        String reply = aiAnalysisService.chatAboutFinding(ctx, request.getRemediationSummary(), snippetBlock, turns);
        return ResponseEntity.ok(Map.of("reply", reply));
    }

    private Application resolveApplicationForEnv(UUID envId) {
        return ephemeralEnvironmentRepository.findByIdWithApplication(envId)
                .map(EphemeralEnvironment::getApplication)
                .orElse(null);
    }

    private String buildFindingContextForAi(Finding f, FindingOccurrence occ, Application app, String snippetForStackInference) {
        StringBuilder sb = new StringBuilder();
        sb.append(ProjectStackInference.buildBlock(f, occ, app, snippetForStackInference));
        sb.append("\n");
        sb.append("title: ").append(nullSafe(f.getTitle())).append("\n");
        sb.append("toolName: ").append(nullSafe(f.getToolName())).append("\n");
        sb.append("scanType: ").append(f.getScanType() != null ? f.getScanType().name() : "").append("\n");
        sb.append("severity: ").append(f.getSeverity() != null ? f.getSeverity().name() : "").append("\n");
        sb.append("ruleId: ").append(nullSafe(f.getRuleId())).append("\n");
        sb.append("description: ").append(nullSafe(f.getDescription())).append("\n");
        sb.append("filePath: ").append(nullSafe(f.getFilePath())).append("\n");
        sb.append("lineStart: ").append(f.getLineStart() != null ? f.getLineStart() : "").append("\n");
        sb.append("lineEnd: ").append(f.getLineEnd() != null ? f.getLineEnd() : "").append("\n");
        sb.append("cve: ").append(nullSafe(f.getCve())).append("\n");
        sb.append("cwe: ").append(nullSafe(f.getCwe())).append("\n");
        sb.append("packageName: ").append(nullSafe(f.getPackageName())).append("\n");
        sb.append("installedVersion: ").append(nullSafe(f.getInstalledVersion())).append("\n");
        sb.append("fixedVersion: ").append(nullSafe(f.getFixedVersion())).append("\n");
        if (occ != null) {
            sb.append("jobName: ").append(nullSafe(occ.getJobName())).append("\n");
            sb.append("artifactPath: ").append(nullSafe(occ.getArtifactPath())).append("\n");
            if (occ.getEvidenceJson() != null && !occ.getEvidenceJson().isEmpty()) {
                try {
                    String ev = objectMapper.writeValueAsString(occ.getEvidenceJson());
                    int max = 10_000;
                    if (ev.length() > max) {
                        ev = ev.substring(0, max) + "...[truncated]";
                    }
                    sb.append("evidence_json: ").append(ev).append("\n");
                } catch (Exception e) {
                    sb.append("evidence_json: <serialization_error>\n");
                }
            }
        }
        return sb.toString();
    }

    private static String nullSafe(String s) {
        return s != null ? s : "";
    }

    /**
     * Stats pour la page « Correctifs IA » : findings SCA par statut (même environnement que les scans).
     */
    @GetMapping("/sca-fixes/stats/by-environment/{envId}")
    public ResponseEntity<Map<String, Object>> scaFixStatsByEnvironment(@PathVariable UUID envId) {
        long openSca = findingRepository.countDistinctByEnvironmentIdAndScanTypeAndStatus(envId, ScanType.SCA, FindingStatus.OPEN);
        long fixedSca = findingRepository.countDistinctByEnvironmentIdAndScanTypeAndStatus(envId, ScanType.SCA, FindingStatus.FIXED);
        long ignoredSca = findingRepository.countDistinctByEnvironmentIdAndScanTypeAndStatus(envId, ScanType.SCA, FindingStatus.IGNORED);
        return ResponseEntity.ok(Map.of(
                "environmentId", envId,
                "openScaCount", openSca,
                "fixedScaCount", fixedSca,
                "ignoredScaCount", ignoredSca
        ));
    }

    /**
     * Liste des vulnérabilités SCA encore ouvertes (correctifs à traiter sur la page Correctifs IA).
     */
    @GetMapping("/sca-fixes/by-environment/{envId}")
    public ResponseEntity<Page<?>> listScaFixesOpenByEnvironment(
            @PathVariable UUID envId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        return ResponseEntity.ok(findingRepository.findByEnvironmentIdAndScanTypeAndStatus(
                envId, ScanType.SCA, FindingStatus.OPEN, PageRequest.of(page, Math.min(size, 200))));
    }

    /**
     * Met à jour le statut d'un finding (ex. ignoré / corrigé manuellement). Vérifie le lien env ↔ occurrence.
     */
    @PatchMapping("/{findingId}/status")
    public ResponseEntity<?> updateFindingStatus(
            @PathVariable UUID findingId,
            @RequestParam UUID envId,
            @Valid @RequestBody FindingStatusUpdateRequest body
    ) {
        if (findingOccurrenceRepository.countByFinding_IdAndPipelineExecution_Environment_Id(findingId, envId) == 0) {
            return ResponseEntity.notFound().build();
        }
        Finding f = findingRepository.findById(findingId).orElse(null);
        if (f == null) {
            return ResponseEntity.notFound().build();
        }
        f.setStatus(body.getStatus());
        findingRepository.save(f);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", f.getId());
        m.put("status", f.getStatus().name());
        return ResponseEntity.ok(m);
    }

    @GetMapping("/by-environment/{envId}")
    public ResponseEntity<Page<?>> listByEnvironment(
            @PathVariable UUID envId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @RequestParam(required = false) String tool,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String scanType,
            @RequestParam(required = false) String status
    ) {
        String toolParam = (tool != null && !tool.isBlank()) ? tool.trim() : null;
        Severity severityEnum = null;
        if (severity != null && !severity.isBlank()) {
            try {
                severityEnum = Severity.valueOf(severity.trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().build();
            }
        }
        ScanType scanTypeEnum = null;
        if (scanType != null && !scanType.isBlank()) {
            try {
                scanTypeEnum = ScanType.valueOf(scanType.trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().build();
            }
        }
        FindingStatus statusEnum = null;
        if (status != null && !status.isBlank()) {
            try {
                statusEnum = FindingStatus.valueOf(status.trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().build();
            }
        }
        if (toolParam == null && severityEnum == null && scanTypeEnum == null && statusEnum == null) {
            return ResponseEntity.ok(findingRepository.findByEnvironmentId(envId, PageRequest.of(page, Math.min(size, 200))));
        }
        // NOTE: on n’applique pas status ici (query env-filtered ne le supporte pas) → fallback : filtre "status"
        // se fait via la vue "by-application" (recommandée quand envId change à chaque test).
        return ResponseEntity.ok(findingRepository.findByEnvironmentIdFiltered(
                envId, toolParam, severityEnum, scanTypeEnum, PageRequest.of(page, Math.min(size, 200))));
    }

    /**
     * Liste paginée au niveau application (utile si chaque test crée un nouvel environnement).
     * Filtrage optionnel: branch/tool/severity/scanType/status.
     */
    @GetMapping("/by-application/{appId}")
    public ResponseEntity<Page<?>> listByApplication(
            @PathVariable UUID appId,
            @RequestParam(required = false) String branch,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @RequestParam(required = false) String tool,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String scanType,
            @RequestParam(required = false) String status
    ) {
        String branchParam = (branch != null && !branch.isBlank()) ? branch.trim() : null;
        String toolParam = (tool != null && !tool.isBlank()) ? tool.trim() : null;

        Severity severityEnum = null;
        if (severity != null && !severity.isBlank()) {
            try {
                severityEnum = Severity.valueOf(severity.trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().build();
            }
        }
        ScanType scanTypeEnum = null;
        if (scanType != null && !scanType.isBlank()) {
            try {
                scanTypeEnum = ScanType.valueOf(scanType.trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().build();
            }
        }
        FindingStatus statusEnum = null;
        if (status != null && !status.isBlank()) {
            try {
                statusEnum = FindingStatus.valueOf(status.trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().build();
            }
        }

        return ResponseEntity.ok(findingRepository.findByApplicationFiltered(
                appId,
                branchParam,
                toolParam,
                severityEnum,
                scanTypeEnum,
                statusEnum,
                PageRequest.of(page, Math.min(size, 200))
        ));
    }

    @GetMapping("/by-pipeline/{pipelineId}")
    public ResponseEntity<Page<?>> listByPipeline(
            @PathVariable Long pipelineId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @RequestParam(required = false) String tool,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String scanType,
            @RequestParam(required = false) String status
    ) {
        String toolParam = (tool != null && !tool.isBlank()) ? tool.trim() : null;
        Severity severityEnum = null;
        if (severity != null && !severity.isBlank()) {
            try {
                severityEnum = Severity.valueOf(severity.trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().build();
            }
        }
        ScanType scanTypeEnum = null;
        if (scanType != null && !scanType.isBlank()) {
            try {
                scanTypeEnum = ScanType.valueOf(scanType.trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().build();
            }
        }
        FindingStatus statusEnum = null;
        if (status != null && !status.isBlank()) {
            try {
                statusEnum = FindingStatus.valueOf(status.trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().build();
            }
        }
        if (toolParam == null && severityEnum == null && scanTypeEnum == null && statusEnum == null) {
            return ResponseEntity.ok(findingRepository.findByGitlabPipelineId(pipelineId, PageRequest.of(page, Math.min(size, 200))));
        }
        return ResponseEntity.ok(findingRepository.findByGitlabPipelineIdFiltered(
                pipelineId, toolParam, severityEnum, scanTypeEnum, statusEnum, PageRequest.of(page, Math.min(size, 200))));
    }

    /**
     * Résout des empreintes (ex. {@code trends.fixedFingerprints}) vers des findings du projet.
     */
    @GetMapping("/by-application/{appId}/fingerprints")
    public ResponseEntity<List<Finding>> listByApplicationFingerprints(
            @PathVariable UUID appId,
            @RequestParam("fp") List<String> fp
    ) {
        if (fp == null || fp.isEmpty()) {
            return ResponseEntity.ok(List.of());
        }
        if (fp.size() > 200) {
            return ResponseEntity.badRequest().build();
        }
        List<String> cleaned = fp.stream().map(String::trim).filter(s -> !s.isEmpty()).distinct().toList();
        if (cleaned.isEmpty()) {
            return ResponseEntity.ok(List.of());
        }
        return ResponseEntity.ok(findingRepository.findDistinctByApplicationIdAndFingerprintIn(appId, cleaned));
    }

    /**
     * MVP: déclenche l'ingestion depuis les artifacts du job "aggregate-report".
     * À brancher ensuite sur le webhook de fin de pipeline (pour automatiser).
     */
    @PostMapping("/ingest/pipeline/{pipelineId}")
    public ResponseEntity<Map<String, Object>> ingestPipeline(@PathVariable Long pipelineId) {
        log.info("Ingestion findings demandée pour pipeline {}", pipelineId);
        try {
            return ResponseEntity.ok(findingIngestionService.ingestFromAggregateArtifacts(pipelineId));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Ingestion findings échouée pipeline {}: {}", pipelineId, e.getMessage());
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Ingestion échouée",
                    "message", e.getMessage()
            ));
        }
    }

    @GetMapping("/stats/by-environment/{envId}")
    public ResponseEntity<Map<String, Object>> statsByEnvironment(@PathVariable UUID envId) {
        var bySeverity = toCountMap(findingOccurrenceRepository.countDistinctFindingsBySeverityForEnv(envId));
        var byTool = toCountMap(findingOccurrenceRepository.countDistinctFindingsByToolForEnv(envId));
        var byScanType = toCountMap(findingOccurrenceRepository.countDistinctFindingsByScanTypeForEnv(envId));

        return ResponseEntity.ok(Map.of(
                "environmentId", envId,
                "bySeverity", bySeverity,
                "byTool", byTool,
                "byScanType", byScanType
        ));
    }

    /**
     * Agrégats pour toute l’application (tous envs).
     * Sans param {@code status} : tous les statuts. Sinon OPEN, FIXED, IGNORED, ACCEPTED_RISK.
     */
    @GetMapping("/stats/by-application/{appId}")
    public ResponseEntity<Map<String, Object>> statsByApplication(
            @PathVariable UUID appId,
            @RequestParam(required = false) String status
    ) {
        FindingStatus st = null;
        if (status != null && !status.isBlank() && !"ALL".equalsIgnoreCase(status.trim())) {
            try {
                st = FindingStatus.valueOf(status.trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().build();
            }
        }
        var bySeverity = toCountMap(
                findingOccurrenceRepository.countDistinctFindingsBySeverityForApplication(appId, st));
        var byTool = toCountMap(
                findingOccurrenceRepository.countDistinctFindingsByToolForApplication(appId, st));
        var byScanType = toCountMap(
                findingOccurrenceRepository.countDistinctFindingsByScanTypeForApplication(appId, st));
        long totalDistinct = bySeverity.values().stream().mapToLong(Long::longValue).sum();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("applicationId", appId);
        body.put("statusFilter", st == null ? "ALL" : st.name());
        body.put("openDistinctTotal", totalDistinct);
        body.put("distinctTotal", totalDistinct);
        body.put("bySeverity", bySeverity);
        body.put("byTool", byTool);
        body.put("byScanType", byScanType);
        return ResponseEntity.ok(body);
    }

    @GetMapping("/stats/by-pipeline/{pipelineId}")
    public ResponseEntity<Map<String, Object>> statsByPipeline(@PathVariable Long pipelineId) {
        var bySeverity = toCountMap(findingOccurrenceRepository.countDistinctFindingsBySeverityForPipeline(pipelineId));
        var byTool = toCountMap(findingOccurrenceRepository.countDistinctFindingsByToolForPipeline(pipelineId));
        var byScanType = toCountMap(findingOccurrenceRepository.countDistinctFindingsByScanTypeForPipeline(pipelineId));

        return ResponseEntity.ok(Map.of(
                "pipelineId", pipelineId,
                "bySeverity", bySeverity,
                "byTool", byTool,
                "byScanType", byScanType
        ));
    }

    /**
     * Compare les 2 derniers pipelines de l'environnement (en base) et renvoie:
     * - new: fingerprints présents dans le dernier pipeline mais pas dans le précédent
     * - fixed: fingerprints présents dans le précédent mais pas dans le dernier
     */
    @GetMapping("/trends/by-environment/{envId}")
    public ResponseEntity<Map<String, Object>> trendsByEnvironment(@PathVariable UUID envId) {
        java.util.List<Long> ids = pipelineExecutionRepository.findGitlabPipelineIdsByEnvironmentIdOrderByCreatedAtDesc(
                envId, org.springframework.data.domain.PageRequest.of(0, 2)
        );
        if (ids.isEmpty()) {
            java.util.Map<String, Object> m = new java.util.HashMap<>();
            m.put("environmentId", envId);
            m.put("lastPipelineId", null);
            m.put("previousPipelineId", null);
            m.put("newCount", 0);
            m.put("fixedCount", 0);
            m.put("newFingerprints", java.util.List.of());
            m.put("fixedFingerprints", java.util.List.of());
            return ResponseEntity.ok(m);
        }
        Long last = ids.get(0);
        Long prev = ids.size() > 1 ? ids.get(1) : null;

        Set<String> lastSet = new HashSet<>(findingOccurrenceRepository.findDistinctFingerprintsByPipeline(last));
        Set<String> prevSet = prev != null ? new HashSet<>(findingOccurrenceRepository.findDistinctFingerprintsByPipeline(prev)) : Set.of();

        Set<String> newOnes = new HashSet<>(lastSet);
        newOnes.removeAll(prevSet);
        Set<String> fixed = new HashSet<>(prevSet);
        fixed.removeAll(lastSet);

        java.util.Map<String, Object> m = new java.util.HashMap<>();
        m.put("environmentId", envId);
        m.put("lastPipelineId", last);
        m.put("previousPipelineId", prev); // peut être null
        m.put("newCount", newOnes.size());
        m.put("fixedCount", fixed.size());
        m.put("newFingerprints", newOnes);
        m.put("fixedFingerprints", fixed);
        return ResponseEntity.ok(m);
    }

    /**
     * Compare les 2 derniers pipelines importés d'une application (en base) et renvoie:
     * - new: fingerprints présents dans le dernier pipeline mais pas dans le précédent
     * - fixed: fingerprints présents dans le précédent mais pas dans le dernier
     *
     * Utile quand chaque pipeline a son environnement (1:1), mais on veut l'évolution "projet".
     * Optionnel: filtrer par branche Git (si env.gitBranch est renseignée).
     */
    @GetMapping("/trends/by-application/{appId}")
    public ResponseEntity<Map<String, Object>> trendsByApplication(
            @PathVariable UUID appId,
            @RequestParam(required = false) String branch
    ) {
        String br = branch != null && !branch.isBlank() ? branch.trim() : null;
        java.util.List<Long> ids = (br == null)
                ? pipelineExecutionRepository.findGitlabPipelineIdsByApplicationIdOrderByCreatedAtDesc(
                    appId, org.springframework.data.domain.PageRequest.of(0, 2))
                : pipelineExecutionRepository.findGitlabPipelineIdsByApplicationIdAndBranchOrderByCreatedAtDesc(
                    appId, br, org.springframework.data.domain.PageRequest.of(0, 2));

        if (ids.isEmpty()) {
            java.util.Map<String, Object> m = new java.util.HashMap<>();
            m.put("applicationId", appId);
            m.put("branch", br);
            m.put("lastPipelineId", null);
            m.put("previousPipelineId", null);
            m.put("newCount", 0);
            m.put("fixedCount", 0);
            m.put("newFingerprints", java.util.List.of());
            m.put("fixedFingerprints", java.util.List.of());
            return ResponseEntity.ok(m);
        }

        Long last = ids.get(0);
        Long prev = ids.size() > 1 ? ids.get(1) : null;

        Set<String> lastSet = new HashSet<>(findingOccurrenceRepository.findDistinctFingerprintsByPipeline(last));
        Set<String> prevSet = prev != null ? new HashSet<>(findingOccurrenceRepository.findDistinctFingerprintsByPipeline(prev)) : Set.of();

        Set<String> newOnes = new HashSet<>(lastSet);
        newOnes.removeAll(prevSet);
        Set<String> fixed = new HashSet<>(prevSet);
        fixed.removeAll(lastSet);

        java.util.Map<String, Object> m = new java.util.HashMap<>();
        m.put("applicationId", appId);
        m.put("branch", br);
        m.put("lastPipelineId", last);
        m.put("previousPipelineId", prev);
        m.put("newCount", newOnes.size());
        m.put("fixedCount", fixed.size());
        m.put("newFingerprints", newOnes);
        m.put("fixedFingerprints", fixed);
        return ResponseEntity.ok(m);
    }

    private Map<String, Long> toCountMap(java.util.List<Object[]> rows) {
        java.util.Map<String, Long> out = new java.util.HashMap<>();
        for (Object[] r : rows) {
            if (r == null || r.length < 2) continue;
            Object k = r[0];
            Object v = r[1];
            if (k == null || v == null) continue;
            out.put(String.valueOf(k), ((Number) v).longValue());
        }
        return out;
    }
}

