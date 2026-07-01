package com.backend.devsecopsplatform_backend.service.finding;

import com.backend.devsecopsplatform_backend.entity.*;
import com.backend.devsecopsplatform_backend.repository.FindingOccurrenceRepository;
import com.backend.devsecopsplatform_backend.repository.FindingRepository;
import com.backend.devsecopsplatform_backend.repository.PipelineExecutionRepository;
import com.backend.devsecopsplatform_backend.repository.SecurityScanRepository;
import com.backend.devsecopsplatform_backend.repository.VulnerabilityRecommendationRepository;
import com.backend.devsecopsplatform_backend.service.GitLabService;
import com.backend.devsecopsplatform_backend.service.qualitygate.PipelineArtifactsIngestedEvent;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.gitlab4j.api.models.Job;
import org.gitlab4j.api.models.JobStatus;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Ingestion des résultats "findings" à partir des artifacts de pipeline.
 *
 * Stratégie MVP: télécharger le ZIP d'artifacts du job "aggregate-report" (qui regroupe reports/)
 * puis parser les JSON connus (trivy, semgrep, gitleaks...) vers un modèle Finding normalisé.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class FindingIngestionService {

    private static final String AGGREGATE_JOB_NAME = "aggregate-report";
    private static final String SECURITY_VALIDATION_JOB_NAME = "security-validation";
    private static final List<String> SUMMARY_ARTIFACT_JOB_NAMES = List.of(
            SECURITY_VALIDATION_JOB_NAME, AGGREGATE_JOB_NAME);

    private final GitLabService gitLabService;
    private final PipelineExecutionRepository pipelineExecutionRepository;
    private final FindingRepository findingRepository;
    private final FindingOccurrenceRepository findingOccurrenceRepository;
    private final SecurityScanRepository securityScanRepository;
    private final VulnerabilityRecommendationRepository vulnerabilityRecommendationRepository;
    private final ObjectMapper objectMapper;
    private final ApplicationEventPublisher eventPublisher;

    @Transactional
    public Map<String, Object> ingestFromAggregateArtifacts(Long pipelineId) {
        ingestSummaryFromPipelineArtifacts(pipelineId);
        return ingestFindingsFromAggregateJob(pipelineId);
    }

    /**
     * Persiste summary.json depuis les artifacts du job security-validation (prioritaire)
     * ou aggregate-report — sans exiger l'ingestion complète des findings.
     */
    @Transactional
    public boolean ingestSummaryFromPipelineArtifacts(Long pipelineId) {
        if (pipelineId == null || pipelineId <= 0) {
            return false;
        }
        PipelineExecution execution = pipelineExecutionRepository.findByGitlabPipelineId(pipelineId)
                .orElse(null);
        if (execution == null) {
            log.warn("summary.json : PipelineExecution introuvable pour pipeline #{}", pipelineId);
            return false;
        }
        for (String jobName : SUMMARY_ARTIFACT_JOB_NAMES) {
            Job job = gitLabService.getJobByName(pipelineId, jobName);
            if (job == null || job.getStatus() != JobStatus.SUCCESS) {
                continue;
            }
            try {
                if (extractAndPersistSummaryFromJobArtifacts(execution, job.getId())) {
                    log.info("summary.json persisté depuis job '{}' pipeline #{}", jobName, pipelineId);
                    return true;
                }
            } catch (Exception e) {
                log.warn("summary.json depuis job '{}' pipeline #{} : {}", jobName, pipelineId, e.getMessage());
            }
        }
        return false;
    }

    @Transactional
    public Map<String, Object> ingestFindingsFromAggregateJob(Long pipelineId) {
        if (pipelineId == null || pipelineId <= 0) {
            throw new IllegalArgumentException("pipelineId invalide");
        }

        PipelineExecution execution = pipelineExecutionRepository.findByGitlabPipelineId(pipelineId)
                .orElseThrow(() -> new IllegalArgumentException("PipelineExecution introuvable en base pour pipelineId=" + pipelineId));

        Job agg = gitLabService.getJobByName(pipelineId, AGGREGATE_JOB_NAME);
        if (agg == null) {
            throw new IllegalStateException("Job '" + AGGREGATE_JOB_NAME + "' introuvable dans le pipeline " + pipelineId);
        }
        if (agg.getStatus() != JobStatus.SUCCESS) {
            throw new IllegalStateException("Job '" + AGGREGATE_JOB_NAME + "' status=" + agg.getStatus() + " (attendu SUCCESS)");
        }

        int parsedFiles = 0;
        int createdFindings = 0;
        int createdOccurrences = 0;
        int autoFixedFindings = 0;
        int createdSecurityScans = 0;
        int createdRecommendations = 0;
        boolean summaryStored = false;
        List<String> parsed = new ArrayList<>();

        try (InputStream zipStream = gitLabService.downloadAllJobArtifacts(agg.getId());
             ZipInputStream zis = new ZipInputStream(zipStream)) {

            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();
                if (entry.isDirectory()) continue;
                if (!name.toLowerCase(Locale.ROOT).endsWith(".json")) continue;
                if (!name.startsWith("reports/") && !name.startsWith("final-report/")) continue;

                JsonNode root;
                try {
                    byte[] content = readZipEntryBytes(zis);
                    root = objectMapper.readTree(content);
                } catch (Exception e) {
                    log.debug("Skip JSON non lisible {}: {}", name, e.getMessage());
                    continue;
                } finally {
                    try {
                        zis.closeEntry();
                    } catch (Exception ignored) {
                        // ignore
                    }
                }

                parsedFiles++;
                parsed.add(name);

                if (isPipelineSummaryArtifact(name)) {
                    try {
                        Map<String, Object> summaryMap = objectMapper.convertValue(
                                root, new TypeReference<Map<String, Object>>() {});
                        persistSummaryOnExecution(execution, summaryMap);
                        summaryStored = true;
                        log.info("summary.json persisté pour pipeline #{}", pipelineId);
                    } catch (Exception e) {
                        log.warn("Impossible de persister summary.json pour pipeline #{}: {}", pipelineId, e.getMessage());
                    }
                    continue;
                }

                List<NormalizedFinding> findings = parseReport(name, root);
                for (NormalizedFinding nf : findings) {
                    String fingerprint = nf.fingerprint();

                    Optional<Finding> existing = findingRepository.findByFingerprint(fingerprint);
                    Finding finding;
                    if (existing.isPresent()) {
                        finding = existing.get();
                    } else {
                        Finding f = new Finding();
                        f.setFingerprint(fingerprint);
                        f.setScanType(nf.scanType);
                        f.setToolName(nf.toolName);
                        f.setSeverity(nf.severity);
                        f.setStatus(FindingStatus.OPEN);
                        f.setRuleId(nf.ruleId);
                        f.setTitle(nf.title);
                        f.setDescription(nf.description);
                        f.setFilePath(nf.filePath);
                        f.setLineStart(nf.lineStart);
                        f.setLineEnd(nf.lineEnd);
                        f.setCve(nf.cve);
                        f.setCwe(nf.cwe);
                        f.setPackageName(nf.packageName);
                        f.setInstalledVersion(nf.installedVersion);
                        f.setFixedVersion(nf.fixedVersion);
                        finding = f;
                        createdFindings++;
                    }

                    finding = findingRepository.save(finding);

                    FindingOccurrence occ = new FindingOccurrence();
                    occ.setFinding(finding);
                    occ.setPipelineExecution(execution);
                    occ.setSecurityScan(null);
                    occ.setToolName(nf.toolName);
                    occ.setJobName(AGGREGATE_JOB_NAME);
                    occ.setArtifactPath(name);
                    occ.setEvidenceJson(nf.evidenceJson);
                    occ.setObservedAt(LocalDateTime.now());
                    findingOccurrenceRepository.save(occ);
                    createdOccurrences++;
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Ingestion artifacts ZIP échouée: " + e.getMessage(), e);
        }

        // SonarCloud/SonarQube (issues/hotspots/QG) vers Findings
        // projectKey du pipeline : EnviroTest_{ENVIRONMENT_ID} (UUID)
        try {
            String envId = execution.getEnvironment() != null && execution.getEnvironment().getId() != null
                    ? execution.getEnvironment().getId().toString()
                    : null;
            String projectKey = envId != null ? "EnviroTest_" + envId : null;
            String branch = execution.getEnvironment() != null ? execution.getEnvironment().getGitBranch() : null;
            int sonarCreated = ingestSonar(execution, projectKey, branch);
            createdFindings += sonarCreated;
        } catch (Exception e) {
            log.warn("⚠️ Ingestion Sonar ignorée (pipelineId={}): {}", pipelineId, e.getMessage());
        }

        // Auto-FIX: si un finding (fingerprint) n’apparait plus dans ce pipeline,
        // on le marque FIXED au niveau de l’application (même branche).
        // Important: on ne peut pas comparer par envId car chaque test crée un env différent.
        try {
            if (createdOccurrences > 0 && execution.getEnvironment() != null && execution.getEnvironment().getApplication() != null) {
                List<String> currentFingerprints = findingOccurrenceRepository.findDistinctFingerprintsByPipeline(pipelineId);
                autoFixedFindings = autoFixFindingsForApplicationBranch(execution, currentFingerprints);
            }
        } catch (Exception e) {
            log.warn("⚠️ Auto-FIX ignoré (pipelineId={}): {}", pipelineId, e.getMessage());
        }

        // Construire une vue “Security scans” persistée (BDD-first) + recommandations basiques.
        // Objectif: éviter un dashboard vide si l’utilisateur n’a pas “cherché” manuellement.
        try {
            Map<String, Object> out = buildAndPersistSecurityScans(execution);
            createdSecurityScans = (int) out.getOrDefault("createdSecurityScans", 0);
            createdRecommendations = (int) out.getOrDefault("createdRecommendations", 0);
        } catch (Exception e) {
            log.warn("⚠️ SecurityScans ignored (pipelineId={}): {}", pipelineId, e.getMessage());
        }

        eventPublisher.publishEvent(new PipelineArtifactsIngestedEvent(execution.getId(), pipelineId));
        log.info("Événement ingestion artifacts publié pour pipeline #{}", pipelineId);

        return Map.of(
                "pipelineId", pipelineId,
                "job", AGGREGATE_JOB_NAME,
                "parsedFiles", parsedFiles,
                "parsed", parsed,
                "summaryStored", summaryStored,
                "createdFindings", createdFindings,
                "createdOccurrences", createdOccurrences,
                "autoFixedFindings", autoFixedFindings,
                "createdSecurityScans", createdSecurityScans,
                "createdRecommendations", createdRecommendations
        );
    }

    /**
     * Regroupe les occurrences de ce pipeline en scans (par tool) et génère des recommandations simples.
     * La version IA peut être branchée plus tard ; ici on veut surtout remplir le dashboard.
     */
    private Map<String, Object> buildAndPersistSecurityScans(PipelineExecution execution) {
        Long pipelineId = execution.getGitlabPipelineId();
        if (pipelineId == null) {
            return Map.of("createdSecurityScans", 0, "createdRecommendations", 0);
        }
        // Recharger toutes les occurrences du pipeline (avec finding via join fetch dans repo "recent",
        // mais ici on utilise la méthode pipelineId -> occurrences lazy: on accède à finding, Hibernate fera le fetch).
        List<FindingOccurrence> occs = findingOccurrenceRepository.findByGitlabPipelineId(pipelineId);
        if (occs == null || occs.isEmpty()) {
            return Map.of("createdSecurityScans", 0, "createdRecommendations", 0);
        }

        // Nettoyer les scans précédents pour ce pipeline (idempotent)
        // Note: cascade des recommendations via orphanRemoval si on delete scans.
        try {
            List<SecurityScan> existing = securityScanRepository.findByPipelineExecutionId(execution.getId());
            if (existing != null && !existing.isEmpty()) {
                securityScanRepository.deleteAll(existing);
            }
        } catch (Exception ignored) {
            // best-effort
        }

        Map<String, List<FindingOccurrence>> byTool = new LinkedHashMap<>();
        for (FindingOccurrence o : occs) {
            String tool = o.getToolName() != null && !o.getToolName().isBlank() ? o.getToolName().trim() : "unknown";
            byTool.computeIfAbsent(tool, k -> new ArrayList<>()).add(o);
        }

        int createdScans = 0;
        int createdRecs = 0;

        for (Map.Entry<String, List<FindingOccurrence>> entry : byTool.entrySet()) {
            String tool = entry.getKey();
            List<FindingOccurrence> toolOccs = entry.getValue();
            if (toolOccs.isEmpty()) continue;

            SecurityScan scan = new SecurityScan();
            scan.setPipelineExecution(execution);
            scan.setToolName(tool);
            // ScanType: on prend le scanType du premier finding si dispo, sinon OTHER
            ScanType st = null;
            try {
                Finding f0 = toolOccs.get(0).getFinding();
                st = f0 != null ? f0.getScanType() : null;
            } catch (Exception ignored) {}
            scan.setScanType(st != null ? st : ScanType.CODE);

            Map<String, Integer> sev = new LinkedHashMap<>();
            List<Map<String, Object>> vulns = new ArrayList<>();

            for (FindingOccurrence o : toolOccs) {
                Finding f = o.getFinding();
                if (f == null) continue;
                String s = f.getSeverity() != null ? f.getSeverity().name() : "MEDIUM";
                sev.put(s, sev.getOrDefault(s, 0) + 1);
                vulns.add(Map.of(
                        "id", String.valueOf(f.getId()),
                        "fingerprint", f.getFingerprint(),
                        "title", f.getTitle() != null ? f.getTitle() : (f.getRuleId() != null ? f.getRuleId() : f.getFingerprint()),
                        "severity", s,
                        "component", f.getPackageName() != null ? f.getPackageName() : (f.getFilePath() != null ? f.getFilePath() : "N/A"),
                        "version", f.getInstalledVersion() != null ? f.getInstalledVersion() : "",
                        "fixedVersion", f.getFixedVersion() != null ? f.getFixedVersion() : ""
                ));
            }

            scan.setSeveritySummary(sev);
            scan.setVulnerabilitiesJson(vulns);

            scan = securityScanRepository.save(scan);
            createdScans++;

            // Recommandations: pour CRITICAL/HIGH, max 20 par scan (sinon trop de bruit)
            int limit = 20;
            for (FindingOccurrence o : toolOccs) {
                if (limit <= 0) break;
                Finding f = o.getFinding();
                if (f == null || f.getSeverity() == null) continue;
                if (!(f.getSeverity() == Severity.CRITICAL || f.getSeverity() == Severity.HIGH)) continue;

                VulnerabilityRecommendation r = new VulnerabilityRecommendation();
                r.setSecurityScan(scan);
                r.setVulnerabilityId(f.getCve() != null ? f.getCve() : (f.getRuleId() != null ? f.getRuleId() : f.getFingerprint()));
                r.setSeverity(f.getSeverity());
                r.setDescription(f.getTitle());
                r.setAiGenerated(false);

                String rec;
                if (f.getFixedVersion() != null && !f.getFixedVersion().isBlank() && f.getInstalledVersion() != null && !f.getInstalledVersion().isBlank()) {
                    rec = "Mettre à jour " + (f.getPackageName() != null ? f.getPackageName() : "le composant")
                            + " de " + f.getInstalledVersion() + " vers " + f.getFixedVersion() + ".";
                } else if (f.getPackageName() != null && !f.getPackageName().isBlank()) {
                    rec = "Vérifier la version du package `" + f.getPackageName() + "` et appliquer le correctif recommandé (upgrade/patch), puis relancer le pipeline.";
                } else if (f.getFilePath() != null && !f.getFilePath().isBlank()) {
                    rec = "Revoir le code dans `" + f.getFilePath() + "` et appliquer une correction conforme à la règle (" +
                            (f.getRuleId() != null ? f.getRuleId() : "security") + "), puis relancer le pipeline.";
                } else {
                    rec = "Appliquer les bonnes pratiques de remédiation, puis relancer le pipeline et ré-importer les résultats.";
                }
                r.setRecommendation(rec);

                vulnerabilityRecommendationRepository.save(r);
                createdRecs++;
                limit--;
            }
        }

        return Map.of("createdSecurityScans", createdScans, "createdRecommendations", createdRecs);
    }

    private int autoFixFindingsForApplicationBranch(PipelineExecution execution, List<String> currentFingerprints) {
        if (currentFingerprints == null || currentFingerprints.isEmpty()) return 0;
        var env = execution.getEnvironment();
        var app = env.getApplication();
        if (env.getGitBranch() == null || env.getGitBranch().isBlank()) return 0;

        List<Finding> toFix = findingRepository.findOpenFindingsForAppBranchNotInFingerprints(
                app.getId(),
                env.getGitBranch(),
                FindingStatus.OPEN,
                currentFingerprints
        );
        int fixed = 0;
        for (Finding f : toFix) {
            // Ne pas écraser les décisions manuelles.
            if (f.getStatus() != FindingStatus.OPEN) continue;
            f.setStatus(FindingStatus.FIXED);
            findingRepository.save(f);
            fixed++;
        }
        if (fixed > 0) {
            log.info("[FINDINGS][AUTO-FIX] appId={} branch={} fixed={} (pipelineId={})",
                    app.getId(), env.getGitBranch(), fixed, execution.getGitlabPipelineId());
        }
        return fixed;
    }

    private static byte[] readZipEntryBytes(ZipInputStream zis) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = zis.read(buffer)) != -1) {
            baos.write(buffer, 0, read);
        }
        return baos.toByteArray();
    }

    private int ingestSonar(PipelineExecution execution, String projectKey, String branch) {
        if (projectKey == null || projectKey.isBlank()) return 0;
        Map<String, Object> sonar = gitLabService.getSonarQubeResultsForProjectKey(projectKey, branch);
        Object issuesObj = sonar.get("issues");
        Object hotspotsObj = sonar.get("hotspots");

        int created = 0;
        if (issuesObj instanceof JsonNode issuesNode && issuesNode.isArray()) {
            List<NormalizedFinding> findings = parseSonarIssues(projectKey, issuesNode);
            created += saveNormalizedFindings(execution, "sonar", findings, "sonar/issues");
        }
        if (hotspotsObj instanceof JsonNode hotspotsNode && hotspotsNode.isArray()) {
            List<NormalizedFinding> findings = parseSonarHotspots(projectKey, hotspotsNode);
            created += saveNormalizedFindings(execution, "sonar", findings, "sonar/hotspots");
        }
        return created;
    }

    private int saveNormalizedFindings(PipelineExecution execution, String tool, List<NormalizedFinding> findings, String artifactPath) {
        int created = 0;
        for (NormalizedFinding nf : findings) {
            String fingerprint = nf.fingerprint();

            Optional<Finding> existing = findingRepository.findByFingerprint(fingerprint);
            Finding finding;
            if (existing.isPresent()) {
                finding = existing.get();
            } else {
                Finding f = new Finding();
                f.setFingerprint(fingerprint);
                f.setScanType(nf.scanType);
                f.setToolName(nf.toolName);
                f.setSeverity(nf.severity);
                f.setStatus(FindingStatus.OPEN);
                f.setRuleId(nf.ruleId);
                f.setTitle(nf.title);
                f.setDescription(nf.description);
                f.setFilePath(nf.filePath);
                f.setLineStart(nf.lineStart);
                f.setLineEnd(nf.lineEnd);
                f.setCve(nf.cve);
                f.setCwe(nf.cwe);
                f.setPackageName(nf.packageName);
                f.setInstalledVersion(nf.installedVersion);
                f.setFixedVersion(nf.fixedVersion);
                finding = f;
                created++;
            }

            finding = findingRepository.save(finding);

            FindingOccurrence occ = new FindingOccurrence();
            occ.setFinding(finding);
            occ.setPipelineExecution(execution);
            occ.setSecurityScan(null);
            occ.setToolName(tool);
            occ.setJobName(AGGREGATE_JOB_NAME);
            occ.setArtifactPath(artifactPath);
            occ.setEvidenceJson(nf.evidenceJson);
            occ.setObservedAt(LocalDateTime.now());
            findingOccurrenceRepository.save(occ);
        }
        return created;
    }

    private List<NormalizedFinding> parseSonarIssues(String projectKey, JsonNode issues) {
        List<NormalizedFinding> out = new ArrayList<>();
        for (JsonNode i : issues) {
            String issueKey = text(i, "key");
            String rule = text(i, "rule");
            String type = text(i, "type");
            String severity = text(i, "severity");
            String message = text(i, "message");
            String component = text(i, "component");
            String file = component != null && component.contains(":") ? component.substring(component.indexOf(':') + 1) : component;

            Integer startLine = null;
            JsonNode tr = i.get("textRange");
            if (tr != null) startLine = intOrNull(tr.get("startLine"));

            Severity sev = toSeverity(severity);
            ScanType scanType = "VULNERABILITY".equalsIgnoreCase(type) ? ScanType.SAST : ScanType.QUALITY;
            String tool = "sonar";
            String title = firstNonBlank(message, rule, issueKey, "Sonar issue");
            String desc = "type=" + nullToEmpty(type) + ", rule=" + nullToEmpty(rule);

            Map<String, Object> evidence = objectMapper.convertValue(i, new TypeReference<>() {});
            String fp = FindingFingerprint.sha256Hex(String.join("|", tool, scanType.name(), nullToEmpty(projectKey), nullToEmpty(issueKey)));
            out.add(new NormalizedFinding(fp, scanType, tool, sev, issueKey, title, desc, file, startLine, startLine, null, null, null, null, null, evidence));
        }
        return out;
    }

    private List<NormalizedFinding> parseSonarHotspots(String projectKey, JsonNode hotspots) {
        List<NormalizedFinding> out = new ArrayList<>();
        for (JsonNode h : hotspots) {
            String hotspotKey = text(h, "key");
            String component = text(h, "component");
            String file = component != null && component.contains(":") ? component.substring(component.indexOf(':') + 1) : component;
            Integer line = intOrNull(h.get("line"));
            String message = firstNonBlank(text(h, "message"), text(h, "securityCategory"), "Security hotspot");

            Severity sev = Severity.MEDIUM;
            ScanType scanType = ScanType.QUALITY;
            String tool = "sonar";
            String title = message;

            Map<String, Object> evidence = objectMapper.convertValue(h, new TypeReference<>() {});
            String fp = FindingFingerprint.sha256Hex(String.join("|", tool, scanType.name(), nullToEmpty(projectKey), "hotspot", nullToEmpty(hotspotKey)));
            out.add(new NormalizedFinding(fp, scanType, tool, sev, hotspotKey, title, null, file, line, line, null, null, null, null, null, evidence));
        }
        return out;
    }

    private List<NormalizedFinding> parseReport(String path, JsonNode root) {
        String p = path.toLowerCase(Locale.ROOT);
        if (p.contains("trivy") && p.endsWith(".json")) {
            return parseTrivy(path, root);
        }
        if (p.contains("gitleaks") && p.endsWith(".json")) {
            return parseGitleaks(path, root);
        }
        // Rapports ESLint / ng lint (JSON tableau de { filePath, messages[] }) — stage sast-angular
        if (p.endsWith(".json") && looksLikeEslintFileResultsArray(root)) {
            return parseEslintStyleIssues(path, root);
        }
        if (p.contains("semgrep") && p.endsWith(".json")) {
            return parseSemgrep(path, root);
        }
        if (p.contains("checkov") && p.endsWith(".json")) {
            return parseCheckov(path, root);
        }
        if (p.contains("grype") && p.endsWith(".json")) {
            return parseGrype(path, root);
        }
        // OWASP DC : rapport JSON souvent nommé dependency-check-report.json ;
        // le job CLI écrit sous reports/owasp/ (le chemin ne contient pas toujours "dependency-check").
        if (p.endsWith(".json") && looksLikeOwaspDependencyCheckReport(path, root)) {
            return parseOwaspDependencyCheck(path, root);
        }
        if (p.contains("npm-audit") && p.endsWith(".json")) {
            return parseNpmAudit(path, root);
        }
        if (p.contains("pip-audit") && p.endsWith(".json")) {
            return parsePipAudit(path, root);
        }
        // PyUp Safety — job pip-audit, fichier safety.json (tableau dépendances + vulnérabilités)
        if (p.endsWith(".json") && (p.contains("safety") || p.contains("/python/safety")) && looksLikeSafetyReport(root)) {
            return parseSafety(path, root);
        }
        if (p.contains("license") && p.endsWith(".json")) {
            return parseLicense(path, root);
        }
        // fallback: ignore (MVP)
        return List.of();
    }

    /**
     * JSON OWASP Dependency-Check : racine {@code dependencies[]} (souvent + projectInfo).
     */
    private boolean looksLikeOwaspDependencyCheckReport(String path, JsonNode root) {
        if (root == null || !root.isObject()) {
            return false;
        }
        String pl = path.toLowerCase(Locale.ROOT);
        if (!(pl.contains("dependency-check")
                || pl.contains("/owasp/")
                || pl.contains("\\owasp\\")
                || pl.contains("/reports/java/")
                || pl.contains("\\reports\\java\\"))) {
            return false;
        }
        JsonNode deps = root.get("dependencies");
        return deps != null && deps.isArray();
    }

    private List<NormalizedFinding> parseTrivy(String path, JsonNode root) {
        // Support Trivy "fs" JSON: Results[].Vulnerabilities[]
        List<NormalizedFinding> out = new ArrayList<>();
        String pl = path != null ? path.toLowerCase(Locale.ROOT) : "";
        boolean imageScan = pl.contains("container-scan") || pl.contains("trivy-image");
        String tool = imageScan ? "trivy-image" : "trivy";
        ScanType scanType = imageScan ? ScanType.CONTAINER : ScanType.SCA;
        JsonNode results = root.get("Results");
        if (results == null || !results.isArray()) {
            results = root.get("results"); // some variants
        }
        if (results == null || !results.isArray()) {
            return out;
        }
        for (JsonNode r : results) {
            JsonNode vulns = r.get("Vulnerabilities");
            if (vulns == null || !vulns.isArray()) continue;
            for (JsonNode v : vulns) {
                String vulnId = text(v, "VulnerabilityID");
                String severity = text(v, "Severity");
                String pkg = text(v, "PkgName");
                String installed = text(v, "InstalledVersion");
                String fixed = text(v, "FixedVersion");
                String title = firstNonBlank(text(v, "Title"), vulnId, "Trivy finding");
                String desc = text(v, "Description");
                String cwe = null;
                String cve = vulnId != null && vulnId.startsWith("CVE-") ? vulnId : null;

                Severity sev = toSeverity(severity);
                String ruleId = vulnId;

                Map<String, Object> evidence = objectMapper.convertValue(v, new TypeReference<>() {
                });
                String fpRaw = String.join("|",
                        tool,
                        scanType.name(),
                        nullToEmpty(vulnId),
                        nullToEmpty(pkg),
                        nullToEmpty(installed),
                        nullToEmpty(fixed),
                        nullToEmpty(text(r, "Target"))
                );
                String fp = FindingFingerprint.sha256Hex(fpRaw);
                out.add(new NormalizedFinding(fp, scanType, tool, sev, ruleId, title, desc,
                        null, null, null, cve, cwe, pkg, installed, fixed, evidence));
            }
        }
        return out;
    }

    private List<NormalizedFinding> parseGitleaks(String path, JsonNode root) {
        // Gitleaks JSON est souvent un tableau d'objets
        List<NormalizedFinding> out = new ArrayList<>();
        if (!root.isArray()) return out;
        for (JsonNode item : root) {
            String ruleId = firstNonBlank(text(item, "RuleID"), text(item, "Rule"), text(item, "rule"));
            String file = firstNonBlank(text(item, "File"), text(item, "file"), text(item, "Path"));
            Integer startLine = intOrNull(item.get("StartLine"));
            Integer endLine = intOrNull(item.get("EndLine"));
            String desc = firstNonBlank(text(item, "Description"), text(item, "description"));

            Severity sev = Severity.HIGH;
            ScanType scanType = ScanType.SECRETS;
            String tool = "gitleaks";
            String title = firstNonBlank(ruleId, "Secret detected");

            Map<String, Object> evidence = objectMapper.convertValue(item, new TypeReference<>() {
            });

            String fpRaw = String.join("|",
                    tool,
                    scanType.name(),
                    nullToEmpty(ruleId),
                    nullToEmpty(file),
                    String.valueOf(startLine != null ? startLine : -1),
                    String.valueOf(endLine != null ? endLine : -1),
                    nullToEmpty(desc)
            );
            String fp = FindingFingerprint.sha256Hex(fpRaw);
            out.add(new NormalizedFinding(fp, scanType, tool, sev, ruleId, title, desc,
                    file, startLine, endLine, null, null, null, null, null, evidence));
        }
        return out;
    }

    private List<NormalizedFinding> parseSemgrep(String path, JsonNode root) {
        List<NormalizedFinding> out = new ArrayList<>();
        JsonNode results = root.get("results");
        if (results == null || !results.isArray()) return out;
        for (JsonNode r : results) {
            String checkId = text(r, "check_id");
            JsonNode pathNode = r.get("path");
            String file = pathNode != null && pathNode.isTextual() ? pathNode.asText() : null;
            JsonNode start = r.path("start");
            JsonNode end = r.path("end");
            Integer startLine = intOrNull(start.get("line"));
            Integer endLine = intOrNull(end.get("line"));
            JsonNode extra = r.get("extra");
            String message = extra != null ? text(extra, "message") : null;
            String severity = extra != null ? text(extra, "severity") : null;

            Severity sev = toSeverity(severity);
            ScanType scanType = ScanType.SAST;
            String tool = "semgrep";
            String title = firstNonBlank(checkId, "Semgrep finding");
            String desc = message;

            Map<String, Object> evidence = objectMapper.convertValue(r, new TypeReference<>() {
            });

            String fpRaw = String.join("|",
                    tool,
                    scanType.name(),
                    nullToEmpty(checkId),
                    nullToEmpty(file),
                    String.valueOf(startLine != null ? startLine : -1),
                    String.valueOf(endLine != null ? endLine : -1),
                    nullToEmpty(message)
            );
            String fp = FindingFingerprint.sha256Hex(fpRaw);
            out.add(new NormalizedFinding(fp, scanType, tool, sev, checkId, title, desc,
                    file, startLine, endLine, null, null, null, null, null, evidence));
        }
        return out;
    }

    private List<NormalizedFinding> parseCheckov(String path, JsonNode root) {
        // Checkov JSON: results.failed_checks[]
        List<NormalizedFinding> out = new ArrayList<>();
        JsonNode failed = root.path("results").path("failed_checks");
        if (!failed.isArray()) return out;
        for (JsonNode c : failed) {
            String checkId = firstNonBlank(text(c, "check_id"), text(c, "checkId"));
            String checkName = text(c, "check_name");
            String file = firstNonBlank(text(c, "file_path"), text(c, "filePath"));
            JsonNode range = c.get("file_line_range");
            Integer start = null;
            Integer end = null;
            if (range != null && range.isArray() && range.size() >= 2) {
                start = intOrNull(range.get(0));
                end = intOrNull(range.get(1));
            }
            String resource = text(c, "resource");
            String desc = firstNonBlank(checkName, resource, checkId);

            Severity sev = Severity.MEDIUM;
            ScanType scanType = ScanType.IAC;
            String tool = "checkov";
            String title = firstNonBlank(checkId, "Checkov finding");

            Map<String, Object> evidence = objectMapper.convertValue(c, new TypeReference<>() {
            });

            String fpRaw = String.join("|",
                    tool, scanType.name(),
                    nullToEmpty(checkId),
                    nullToEmpty(file),
                    String.valueOf(start != null ? start : -1),
                    nullToEmpty(resource)
            );
            String fp = FindingFingerprint.sha256Hex(fpRaw);
            out.add(new NormalizedFinding(fp, scanType, tool, sev, checkId, title, desc, file, start, end,
                    null, null, null, null, null, evidence));
        }
        return out;
    }

    private List<NormalizedFinding> parseGrype(String path, JsonNode root) {
        // Grype JSON: matches[].vulnerability.{id,severity}, artifact.{name,version}
        List<NormalizedFinding> out = new ArrayList<>();
        JsonNode matches = root.get("matches");
        if (matches == null || !matches.isArray()) return out;
        for (JsonNode m : matches) {
            JsonNode vuln = m.get("vulnerability");
            if (vuln == null) continue;
            String vulnId = text(vuln, "id");
            String severity = text(vuln, "severity");
            JsonNode artifact = m.get("artifact");
            String name = artifact != null ? text(artifact, "name") : null;
            String version = artifact != null ? text(artifact, "version") : null;

            Severity sev = toSeverity(severity);
            ScanType scanType = ScanType.CONTAINER;
            String tool = "grype";
            String title = firstNonBlank(vulnId, "Grype finding");

            Map<String, Object> evidence = objectMapper.convertValue(m, new TypeReference<>() {
            });

            String fpRaw = String.join("|",
                    tool, scanType.name(),
                    nullToEmpty(vulnId),
                    nullToEmpty(name),
                    nullToEmpty(version)
            );
            String fp = FindingFingerprint.sha256Hex(fpRaw);
            out.add(new NormalizedFinding(fp, scanType, tool, sev, vulnId, title, null,
                    null, null, null,
                    vulnId != null && vulnId.startsWith("CVE-") ? vulnId : null,
                    null, name, version, null, evidence));
        }
        return out;
    }

    private List<NormalizedFinding> parseOwaspDependencyCheck(String path, JsonNode root) {
        // OWASP DC JSON: dependencies[].vulnerabilities[]
        List<NormalizedFinding> out = new ArrayList<>();
        JsonNode deps = root.get("dependencies");
        if (deps == null || !deps.isArray()) return out;
        String pl = path != null ? path.toLowerCase(Locale.ROOT) : "";
        String toolBase;
        if (pl.contains("/owasp/") || pl.contains("\\owasp\\")) {
            toolBase = "owasp-dependency-check";
        } else if (pl.contains("/java/") || pl.contains("\\java\\")) {
            toolBase = "maven-dependency-check";
        } else {
            toolBase = "dependency-check";
        }
        for (JsonNode d : deps) {
            String fileName = text(d, "fileName");
            JsonNode vulns = d.get("vulnerabilities");
            if (vulns == null || !vulns.isArray()) continue;
            for (JsonNode v : vulns) {
                String name = firstNonBlank(text(v, "name"), text(v, "vulnId"));
                String severity = text(v, "severity");
                String desc = text(v, "description");
                Severity sev = toSeverity(severity);
                ScanType scanType = ScanType.SCA;
                String tool = toolBase;
                String title = firstNonBlank(name, "Dependency-Check finding");

                Map<String, Object> evidence = objectMapper.convertValue(v, new TypeReference<>() {
                });

                String fpRaw = String.join("|",
                        tool, scanType.name(),
                        nullToEmpty(name),
                        nullToEmpty(fileName)
                );
                String fp = FindingFingerprint.sha256Hex(fpRaw);
                out.add(new NormalizedFinding(fp, scanType, tool, sev, name, title, desc,
                        null, null, null,
                        name != null && name.startsWith("CVE-") ? name : null,
                        null, fileName, null, null, evidence));
            }
        }
        return out;
    }

    private List<NormalizedFinding> parseNpmAudit(String path, JsonNode root) {
        // npm audit --json (npm v7+): vulnerabilities{ name: {severity,via,range,fixAvailable} }
        List<NormalizedFinding> out = new ArrayList<>();
        JsonNode vulns = root.get("vulnerabilities");
        if (vulns == null || !vulns.isObject()) return out;
        Iterator<String> names = vulns.fieldNames();
        while (names.hasNext()) {
            String pkg = names.next();
            JsonNode v = vulns.get(pkg);
            String severity = text(v, "severity");
            Severity sev = toSeverity(severity);
            ScanType scanType = ScanType.SCA;
            String tool = "npm-audit";
            String title = "npm audit: " + pkg;
            Map<String, Object> evidence = objectMapper.convertValue(v, new TypeReference<>() {
            });
            String fp = FindingFingerprint.sha256Hex(String.join("|", tool, scanType.name(), pkg, nullToEmpty(severity)));
            out.add(new NormalizedFinding(fp, scanType, tool, sev, pkg, title, null,
                    null, null, null, null, null, pkg, null, null, evidence));
        }
        return out;
    }

    private List<NormalizedFinding> parsePipAudit(String path, JsonNode root) {
        // pip-audit --format json : souvent une liste d'objets avec name, version, id (CVE), description, fix_versions
        List<NormalizedFinding> out = new ArrayList<>();
        if (!root.isArray()) return out;
        for (JsonNode v : root) {
            String pkg = firstNonBlank(text(v, "name"), text(v, "package"));
            String ver = firstNonBlank(text(v, "version"), text(v, "installed_version"));
            String vulnId = firstNonBlank(text(v, "id"), text(v, "vuln_id"), text(v, "cve"));
            String desc = text(v, "description");
            Severity sev = Severity.MEDIUM;
            ScanType scanType = ScanType.SCA;
            String tool = "pip-audit";
            String title = firstNonBlank(vulnId, pkg, "pip-audit finding");
            Map<String, Object> evidence = objectMapper.convertValue(v, new TypeReference<>() {
            });
            String fp = FindingFingerprint.sha256Hex(String.join("|", tool, scanType.name(), nullToEmpty(vulnId), nullToEmpty(pkg), nullToEmpty(ver)));
            out.add(new NormalizedFinding(fp, scanType, tool, sev, vulnId, title, desc,
                    null, null, null,
                    vulnId != null && vulnId.startsWith("CVE-") ? vulnId : null,
                    null, pkg, ver, null, evidence));
        }
        return out;
    }

    private List<NormalizedFinding> parseLicense(String path, JsonNode root) {
        // license-checker / licensecheck: format variable. MVP: stocker le package comme "finding" info/low.
        List<NormalizedFinding> out = new ArrayList<>();
        ScanType scanType = ScanType.LICENSE;
        String tool = "license";

        if (root.isObject()) {
            Iterator<String> pkgs = root.fieldNames();
            while (pkgs.hasNext()) {
                String pkg = pkgs.next();
                JsonNode v = root.get(pkg);
                String licenses = firstNonBlank(text(v, "licenses"), text(v, "license"), v.isTextual() ? v.asText() : null);
                Severity sev = Severity.INFO;
                String title = "License: " + pkg;
                Map<String, Object> evidence = objectMapper.convertValue(v, new TypeReference<>() {
                });
                String fp = FindingFingerprint.sha256Hex(String.join("|", tool, scanType.name(), pkg, nullToEmpty(licenses)));
                out.add(new NormalizedFinding(fp, scanType, tool, sev, pkg, title, licenses,
                        null, null, null, null, null, pkg, null, null, evidence));
            }
        } else if (root.isArray()) {
            for (JsonNode v : root) {
                String pkg = firstNonBlank(text(v, "package"), text(v, "name"));
                String lic = firstNonBlank(text(v, "license"), text(v, "licenses"));
                Severity sev = Severity.INFO;
                String title = "License: " + pkg;
                Map<String, Object> evidence = objectMapper.convertValue(v, new TypeReference<>() {
                });
                String fp = FindingFingerprint.sha256Hex(String.join("|", tool, scanType.name(), nullToEmpty(pkg), nullToEmpty(lic)));
                out.add(new NormalizedFinding(fp, scanType, tool, sev, pkg, title, lic,
                        null, null, null, null, null, pkg, null, null, evidence));
            }
        }
        return out;
    }

    /** Sortie standard ESLint / ng lint : tableau de { "filePath", "messages": [...] }. */
    private boolean looksLikeEslintFileResultsArray(JsonNode root) {
        if (root == null || !root.isArray() || root.size() == 0) {
            return false;
        }
        JsonNode first = root.get(0);
        return first != null && first.isObject()
                && first.has("filePath")
                && first.get("messages") != null
                && first.get("messages").isArray();
    }

    private List<NormalizedFinding> parseEslintStyleIssues(String path, JsonNode root) {
        List<NormalizedFinding> out = new ArrayList<>();
        if (!root.isArray()) {
            return out;
        }
        String pl = path != null ? path.toLowerCase(Locale.ROOT) : "";
        String tool;
        if (pl.contains("angular-lint")) {
            tool = "ng-lint";
        } else if (pl.contains("react-lint")) {
            tool = "eslint";
        } else if (pl.contains("safe-report")) {
            tool = "safe";
        } else {
            tool = "eslint";
        }
        for (JsonNode fileNode : root) {
            String filePath = text(fileNode, "filePath");
            JsonNode messages = fileNode.get("messages");
            if (messages == null || !messages.isArray()) {
                continue;
            }
            for (JsonNode m : messages) {
                String ruleId = text(m, "ruleId");
                if (ruleId == null || ruleId.isBlank()) {
                    continue;
                }
                String msg = firstNonBlank(text(m, "message"), ruleId);
                int sevNum = m.has("severity") && m.get("severity").isNumber() ? m.get("severity").asInt() : 1;
                Severity sev = sevNum >= 2 ? Severity.HIGH : Severity.MEDIUM;
                Integer line = intOrNull(m.get("line"));
                Map<String, Object> evidence = objectMapper.convertValue(m, new TypeReference<>() {});
                String fpRaw = String.join("|", tool, ScanType.SAST.name(), nullToEmpty(ruleId), nullToEmpty(filePath),
                        String.valueOf(line != null ? line : -1), nullToEmpty(msg));
                String fp = FindingFingerprint.sha256Hex(fpRaw);
                out.add(new NormalizedFinding(fp, ScanType.SAST, tool, sev, ruleId, msg, null,
                        filePath, line, line, null, null, null, null, null, evidence));
            }
        }
        return out;
    }

    private boolean looksLikeSafetyReport(JsonNode root) {
        if (root == null || !root.isArray() || root.size() == 0) {
            return false;
        }
        JsonNode first = root.get(0);
        if (first == null || !first.isObject()) {
            return false;
        }
        return first.has("vulnerabilities") || first.has("package_name") || first.has("package");
    }

    /**
     * PyUp Safety JSON (souvent un tableau de dépendances avec {@code vulnerabilities[]}).
     */
    private List<NormalizedFinding> parseSafety(String path, JsonNode root) {
        List<NormalizedFinding> out = new ArrayList<>();
        if (!root.isArray()) {
            return out;
        }
        String tool = "safety";
        for (JsonNode dep : root) {
            if (dep == null || !dep.isObject()) {
                continue;
            }
            String pkg = firstNonBlank(text(dep, "package_name"), text(dep, "package"), text(dep, "spec"));
            String ver = firstNonBlank(text(dep, "installed_version"), text(dep, "version"), text(dep, "installed"));
            JsonNode vulns = dep.get("vulnerabilities");
            if (vulns == null || !vulns.isArray()) {
                continue;
            }
            for (JsonNode v : vulns) {
                String vid = firstNonBlank(text(v, "vulnerability_id"), text(v, "id"), text(v, "cve_id"),
                        text(v, "cve"), text(v, "CVE"));
                String desc = firstNonBlank(text(v, "advisory"), text(v, "description"), text(v, "details"));
                Severity sev = toSeverity(text(v, "severity"));
                String title = firstNonBlank(vid, pkg, "Safety finding");
                Map<String, Object> evidence = objectMapper.convertValue(v, new TypeReference<>() {});
                String fp = FindingFingerprint.sha256Hex(String.join("|", tool, ScanType.SCA.name(),
                        nullToEmpty(vid), nullToEmpty(pkg), nullToEmpty(ver)));
                String cve = vid != null && vid.startsWith("CVE-") ? vid : null;
                out.add(new NormalizedFinding(fp, ScanType.SCA, tool, sev, vid, title, desc,
                        null, null, null, cve, null, pkg, ver, null, evidence));
            }
        }
        return out;
    }

    private static Severity toSeverity(String s) {
        if (s == null) return Severity.MEDIUM;
        String v = s.trim().toUpperCase(Locale.ROOT);
        return switch (v) {
            case "CRITICAL" -> Severity.CRITICAL;
            case "HIGH", "ERROR" -> Severity.HIGH;
            case "MEDIUM", "WARNING" -> Severity.MEDIUM;
            case "LOW" -> Severity.LOW;
            default -> Severity.INFO;
        };
    }

    private static String text(JsonNode node, String field) {
        if (node == null) return null;
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) return null;
        if (v.isTextual()) return v.asText();
        return v.toString();
    }

    private static Integer intOrNull(JsonNode node) {
        if (node == null || node.isNull()) return null;
        if (node.isInt() || node.isLong()) return node.asInt();
        if (node.isTextual()) {
            try {
                return Integer.parseInt(node.asText().trim());
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    private static String firstNonBlank(String... vals) {
        if (vals == null) return null;
        for (String v : vals) {
            if (v != null && !v.isBlank()) return v;
        }
        return null;
    }

    private static String nullToEmpty(String v) {
        return v == null ? "" : v;
    }

    private static boolean isPipelineSummaryArtifact(String name) {
        if (name == null) return false;
        String n = name.replace('\\', '/').toLowerCase(Locale.ROOT);
        return n.endsWith("final-report/summary.json") || n.endsWith("/summary.json");
    }

    private boolean extractAndPersistSummaryFromJobArtifacts(PipelineExecution execution, Long jobId) throws Exception {
        try (InputStream zipStream = gitLabService.downloadAllJobArtifacts(jobId);
             ZipInputStream zis = new ZipInputStream(zipStream)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();
                if (entry.isDirectory()) continue;
                if (!isPipelineSummaryArtifact(name)) continue;
                try {
                    byte[] content = readZipEntryBytes(zis);
                    JsonNode root = objectMapper.readTree(content);
                    Map<String, Object> summaryMap = objectMapper.convertValue(
                            root, new TypeReference<Map<String, Object>>() {});
                    persistSummaryOnExecution(execution, summaryMap);
                    return true;
                } finally {
                    try {
                        zis.closeEntry();
                    } catch (Exception ignored) {
                        // ignore
                    }
                }
            }
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    private void persistSummaryOnExecution(PipelineExecution execution, Map<String, Object> summary) {
        Map<String, Object> gate = execution.getQualityGateJson();
        if (gate == null) {
            gate = new LinkedHashMap<>();
        }
        gate.put("summary", summary);
        gate.put("summarySavedAt", Instant.now().toString());
        persistSonarSqFieldsOnSummary(gate, summary);
        if (summary.get("pipeline_id") != null) {
            gate.put("pipelineId", String.valueOf(summary.get("pipeline_id")));
        }
        execution.setQualityGateJson(gate);
        pipelineExecutionRepository.save(execution);
    }

    @SuppressWarnings("unchecked")
    private void persistSonarSqFieldsOnSummary(Map<String, Object> gate, Map<String, Object> summary) {
        if (gate == null || summary == null || !(summary.get("sonar") instanceof Map<?, ?> sonar)) {
            return;
        }
        Map<String, Object> s = (Map<String, Object>) sonar;
        putPositive(gate, "sonarSqSecurityIssues", s.get("software_quality_security_issues"));
        putPositive(gate, "sonarSqReliabilityIssues", s.get("software_quality_reliability_issues"));
        putPositive(gate, "sonarSqMaintainabilityIssues", s.get("software_quality_maintainability_issues"));
        Object secRate = firstNonBlank(
                ratingLetter(s.get("software_quality_security_rating")),
                ratingLetter(s.get("security_rating")));
        Object relRate = firstNonBlank(
                ratingLetter(s.get("software_quality_reliability_rating")),
                ratingLetter(s.get("reliability_rating")));
        Object maintRate = firstNonBlank(
                ratingLetter(s.get("software_quality_maintainability_rating")),
                ratingLetter(s.get("sqale_rating")));
        if (secRate != null) gate.put("sonarSqSecurityRating", secRate);
        if (relRate != null) gate.put("sonarSqReliabilityRating", relRate);
        if (maintRate != null) gate.put("sonarSqMaintainabilityRating", maintRate);
    }

    private void putPositive(Map<String, Object> gate, String key, Object value) {
        if (value == null) return;
        try {
            int n = value instanceof Number num ? num.intValue() : Integer.parseInt(String.valueOf(value).trim());
            if (n > 0) gate.put(key, n);
        } catch (Exception ignored) {
        }
    }

    private String ratingLetter(Object raw) {
        if (raw == null) return null;
        String s = String.valueOf(raw).trim().toUpperCase(Locale.ROOT);
        if (s.length() == 1 && s.charAt(0) >= 'A' && s.charAt(0) <= 'E') return s;
        try {
            int n = (int) Math.round(Double.parseDouble(s));
            return switch (n) {
                case 1 -> "A";
                case 2 -> "B";
                case 3 -> "C";
                case 4 -> "D";
                case 5 -> "E";
                default -> null;
            };
        } catch (Exception e) {
            return null;
        }
    }

    private record NormalizedFinding(
            String fingerprint,
            ScanType scanType,
            String toolName,
            Severity severity,
            String ruleId,
            String title,
            String description,
            String filePath,
            Integer lineStart,
            Integer lineEnd,
            String cve,
            String cwe,
            String packageName,
            String installedVersion,
            String fixedVersion,
            Map<String, Object> evidenceJson
    ) {
    }
}

