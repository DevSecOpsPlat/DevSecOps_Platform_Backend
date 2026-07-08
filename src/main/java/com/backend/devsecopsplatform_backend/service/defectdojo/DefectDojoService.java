package com.backend.devsecopsplatform_backend.service.defectdojo;

import com.backend.devsecopsplatform_backend.configuration.DefectDojoProperties;
import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.AppServiceRepository;
import com.backend.devsecopsplatform_backend.repository.EphemeralEnvironmentRepository;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import com.backend.devsecopsplatform_backend.service.SourceSnippetFetcherService;
import com.backend.devsecopsplatform_backend.service.defectdojo.dto.*;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class DefectDojoService {

    private static final List<String> SEVERITIES = List.of("Critical", "High", "Medium", "Low", "Info");

    /** Définition UNIQUE d'un finding « ouvert » — KPI, cartes, liste et charts. */
    private static final Map<String, String> OPEN_FILTERS = Map.of(
            "active", "true",
            "is_mitigated", "false",
            "duplicate", "false",
            "false_p", "false",
            "out_of_scope", "false");

    private static Map<String, String> openFiltersWithSeverity(String severity) {
        Map<String, String> p = new LinkedHashMap<>(OPEN_FILTERS);
        p.put("severity", severity);
        return p;
    }

    private static List<JsonNode> filterCurrentlyOpenFindings(List<JsonNode> findings) {
        if (findings == null || findings.isEmpty()) {
            return List.of();
        }
        return findings.stream().filter(DefectDojoService::isCurrentlyOpen).toList();
    }

    /** Pool I/O DefectDojo — tâches feuilles uniquement (pas de join imbriqué sur ce pool). */
    private static final ExecutorService DD_IO_POOL = Executors.newFixedThreadPool(
            12,
            r -> {
                Thread t = new Thread(r, "defectdojo-io");
                t.setDaemon(true);
                return t;
            }
    );

    private final DefectDojoProperties properties;
    private final AppServiceRepository applicationRepository;
    private final EphemeralEnvironmentRepository environmentRepository;
    private final UserRepository userRepository;
    private final SourceSnippetFetcherService sourceSnippetFetcherService;
    private final DefectDojoHttpClientFactory httpClientFactory;

    private record EngagementContext(
            AppService application,
            String productName,
            String branch,
            String engagementName,
            int productId,
            int engagementId
    ) {}

    private volatile String lastApiError;
    private volatile Integer cachedApiUserId;

    public DefectDojoDashboardResponse getDashboard(UUID applicationId, String branch, String tags) {
        return getDashboard(applicationId, branch, tags, true);
    }

    @Cacheable(
            value = "defectDojoDashboard",
            key = "#applicationId + '|' + (#branch ?: '') + '|' + (#tags ?: '') + '|' + #includeCharts",
            unless = "#result == null || !#result.configured || #result.engagementId == null"
    )
    public DefectDojoDashboardResponse getDashboard(UUID applicationId, String branch, String tags, boolean includeCharts) {
        if (!properties.isConfigured()) {
            return DefectDojoDashboardResponse.builder()
                    .configured(false)
                    .message("DefectDojo n'est pas configuré (DEFECTDOJO_URL / DEFECTDOJO_TOKEN).")
                    .build();
        }

        User user = currentUser();
        AppService app = applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));

        String productName = extractRepoName(app.getGitRepositoryUrl());
        String effectiveBranch = resolveBranch(applicationId, user, branch);
        String engagementName = productName + "_" + effectiveBranch;

        JsonNode product = findProduct(productName);
        if (product == null) {
            return baseResponse(productName, effectiveBranch, engagementName)
                    .message("Produit DefectDojo « " + productName + " » introuvable. Lancez d'abord une analyse (pipeline import-defectdojo).")
                    .availableEngagements(listLocalBranches(applicationId, user))
                    .build();
        }

        int productId = product.path("id").asInt();
        JsonNode engagement = findEngagement(productId, engagementName);
        if (engagement == null) {
            return baseResponse(productName, effectiveBranch, engagementName)
                    .configured(true)
                    .productId(productId)
                    .productUrl(productUiUrl(productId))
                    .engagementName(engagementName)
                    .branch(effectiveBranch)
                    .message("Engagement « " + engagementName + " » introuvable pour la branche « " + effectiveBranch + " ».")
                    .availableEngagements(listEngagementsForProduct(productId, productName))
                    .defectDojoBaseUrl(properties.normalizedBaseUrl())
                    .build();
        }

        int engagementId = engagement.path("id").asInt();
        String trimmedTags = tags != null ? tags.trim() : null;
        boolean testScopedTag = isTestScopedTag(trimmedTags);

        Map<String, Integer> bySeverity = testScopedTag
                ? parallelCountBySeverityForTaggedTests(engagementId, trimmedTags)
                : countBySeverityParallel(engagementId, tags);
        Map<String, Integer> byStatus = countByStatus(engagementId, tags);
        List<DefectDojoMetricCard> metricCards = buildMetricCardsParallel(
                engagementId, tags, CompletableFuture.completedFuture(bySeverity));

        int critical = bySeverity.getOrDefault("Critical", 0);
        int high = bySeverity.getOrDefault("High", 0);
        int totalActive = byStatus.getOrDefault("active", 0);
        int totalMitigated = byStatus.getOrDefault("mitigated", 0);

        DefectDojoDashboardCharts charts = null;
        if (includeCharts) {
            charts = buildChartsParallel(engagementId, productId, bySeverity, byStatus, totalActive, totalMitigated, tags);
        }

        return baseResponse(productName, effectiveBranch, engagementName)
                .configured(true)
                .productId(productId)
                .productUrl(productUiUrl(productId))
                .engagementId(engagementId)
                .engagementName(engagementName)
                .engagementUrl(engagementUiUrl(engagementId))
                .engagementStatus(engagement.path("status").asText(null))
                .branch(effectiveBranch)
                .bySeverity(bySeverity)
                .byStatus(byStatus)
                .totalActive(totalActive)
                .totalMitigated(totalMitigated)
                .totalFindings(totalActive + totalMitigated)
                .metricCards(metricCards)
                .charts(charts)
                .availableEngagements(listEngagementsForProductLight(productId, productName))
                .deployRecommendation(buildRecommendation(critical, high))
                .defectDojoBaseUrl(properties.normalizedBaseUrl())
                .build();
    }

    @Cacheable(
            value = "defectDojoDashboard",
            key = "#applicationId + '|' + (#branch ?: '') + '|' + (#tags ?: '') + '|charts'",
            unless = "#result == null"
    )
    public DefectDojoDashboardCharts getDashboardCharts(UUID applicationId, String branch, String tags) {
        if (!properties.isConfigured()) {
            return DefectDojoDashboardCharts.builder()
                    .scanSnapshots(List.of())
                    .bySeverity(emptySeverityMap())
                    .build();
        }

        User user = currentUser();
        AppService app = applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));

        String productName = extractRepoName(app.getGitRepositoryUrl());
        String effectiveBranch = resolveBranch(applicationId, user, branch);
        String engagementName = productName + "_" + effectiveBranch;

        JsonNode product = findProduct(productName);
        if (product == null) {
            return DefectDojoDashboardCharts.builder()
                    .scanSnapshots(List.of())
                    .bySeverity(emptySeverityMap())
                    .build();
        }

        int productId = product.path("id").asInt();
        JsonNode engagement = findEngagement(productId, engagementName);
        if (engagement == null) {
            return DefectDojoDashboardCharts.builder()
                    .scanSnapshots(List.of())
                    .bySeverity(emptySeverityMap())
                    .build();
        }

        int engagementId = engagement.path("id").asInt();
        String trimmedTags = tags != null ? tags.trim() : null;

        return buildChartsParallel(engagementId, productId, trimmedTags, tags);
    }

    private DefectDojoDashboardCharts buildChartsParallel(
            int engagementId,
            int productId,
            String trimmedTags,
            String tags
    ) {
        boolean envTag = isEnvironmentTag(trimmedTags);
        Map<String, Integer> bySeverity = envTag
                ? parallelCountBySeverityForTaggedTests(engagementId, trimmedTags)
                : countBySeverityParallel(engagementId, tags);
        Map<String, Integer> byStatus = countByStatus(engagementId, tags);
        int totalActive = byStatus.getOrDefault("active", 0);
        int totalMitigated = byStatus.getOrDefault("mitigated", 0);

        List<JsonNode> timelineFindings = fetchAllEngagementFindings(engagementId);
        List<JsonNode> openFindings = filterCurrentlyOpenFindings(timelineFindings);
        List<DefectDojoScanSnapshot> scanSnapshots = buildScanSnapshotsFast(engagementId);

        return buildChartsFromParts(
                bySeverity,
                byStatus,
                totalActive,
                totalMitigated,
                openFindings,
                timelineFindings,
                scanSnapshots
        );
    }

    private DefectDojoDashboardCharts buildChartsParallel(
            int engagementId,
            int productId,
            Map<String, Integer> bySeverity,
            Map<String, Integer> byStatus,
            int totalActive,
            int totalMitigated,
            String tags
    ) {
        List<JsonNode> timelineFindings = fetchAllEngagementFindings(engagementId);
        List<JsonNode> openFindings = filterCurrentlyOpenFindings(timelineFindings);
        List<DefectDojoScanSnapshot> scanSnapshots = buildScanSnapshotsFast(engagementId);

        return buildChartsFromParts(
                bySeverity,
                byStatus,
                totalActive,
                totalMitigated,
                openFindings,
                timelineFindings,
                scanSnapshots
        );
    }

    private static boolean isEnvironmentTag(String tags) {
        return isTestScopedTag(tags);
    }

    private static boolean isTestScopedTag(String tags) {
        if (tags == null || tags.isBlank()) {
            return false;
        }
        String t = tags.trim();
        return t.startsWith("env-") || t.startsWith("pipeline-") || SCAN_KIND_TAG.equals(t) || DEPLOY_KIND_TAG.equals(t);
    }

    public static final String SCAN_KIND_TAG = "scan";
    public static final String DEPLOY_KIND_TAG = "deploy";

    /**
     * Dashboard sécurité v2 : vue globale (produit) par défaut, ou filtrée par branche/engagement.
     * Ne dépend pas d'un pipeline en cours — données DefectDojo immédiates (0 si absent).
     */
    public DefectDojoDashboard2Response getDashboard2(UUID applicationId, String branch) {
        return getDashboard2(applicationId, branch, null, null, true);
    }

    /**
     * Dashboard v2 filtré par branche et optionnellement par environnement éphémère
     * (tag {@code env-<uuid>}, legacy) ou par pipeline GitLab ({@code pipeline-<id>}).
     */
    public DefectDojoDashboard2Response getDashboard2(UUID applicationId, String branch, UUID environmentId) {
        return getDashboard2(applicationId, branch, environmentId, null, true);
    }

    public DefectDojoDashboard2Response getDashboard2(
            UUID applicationId,
            String branch,
            UUID environmentId,
            Long pipelineId
    ) {
        return getDashboard2(applicationId, branch, environmentId, pipelineId, true);
    }

    public DefectDojoDashboard2Response getDashboard2(
            UUID applicationId,
            String branch,
            UUID environmentId,
            Long pipelineId,
            boolean scanOnly
    ) {
        User user = currentUser();
        String filterTag = resolveDashboardFilterTag(environmentId, pipelineId, scanOnly);
        AppService app = applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));

        String productName = extractRepoName(app.getGitRepositoryUrl());
        boolean global = isGlobalBranch(branch);

        if (!properties.isConfigured()) {
            List<String> branches = listBranches(applicationId);
            return emptyDashboard2(app, productName, global, branches)
                    .configured(false)
                    .message("DefectDojo n'est pas configuré (DEFECTDOJO_URL / DEFECTDOJO_TOKEN).")
                    .build();
        }

        JsonNode product = findProduct(productName);
        if (product == null) {
            List<String> branches = listBranches(applicationId);
            return emptyDashboard2(app, productName, global, branches)
                    .configured(true)
                    .message(explainMissingProduct(productName))
                    .build();
        }

        int productId = product.path("id").asInt();
        List<DefectDojoEngagementSummary> engagements = listEngagementsForProductLight(productId, productName);
        List<String> branches = branchNamesFromEngagements(applicationId, productName, engagements);

        if (global) {
            Map<String, Integer> bySeverity = parallelCountBySeverityForProduct(productId);
            Map<String, Integer> byStatus = parallelCountByStatusLightForProduct(productId);
            int open = bySeverity.values().stream().mapToInt(Integer::intValue).sum();
            int closed = byStatus.getOrDefault("mitigated", 0);
            List<JsonNode> openSample = fetchOpenFindingsSample(productId, null, 150);
            Map<String, Integer> byTool = aggregateToolsFromProductTests(productId);
            if (byTool.isEmpty() && !openSample.isEmpty()) {
                byTool = aggregateToolsFromFindings(openSample);
            }
            DefectDojoDashboardCharts charts = buildDashboard2ChartsForGlobal(productId, bySeverity, engagements);

            return DefectDojoDashboard2Response.builder()
                    .configured(true)
                    .scope("global")
                    .applicationName(app.getName())
                    .productName(productName)
                    .productId(productId)
                    .productUrl(productUiUrl(productId))
                    .selectedBranch(null)
                    .bySeverity(bySeverity)
                    .byTool(byTool)
                    .byStatus(byStatus)
                    .totalOpen(open)
                    .totalClosed(closed)
                    .securityScore(computeSecurityScore(bySeverity))
                    .topRecurrent(buildTopRecurrent(openSample, 3))
                    .trendPoints(List.of())
                    .branches(branches)
                    .engagements(engagements)
                    .charts(charts)
                    .defectDojoBaseUrl(properties.normalizedBaseUrl())
                    .build();
        }

        String effectiveBranch = branch != null ? branch.trim() : "main";
        String engagementName = productName + "_" + effectiveBranch;
        JsonNode engagement = findEngagement(productId, engagementName);
        if (engagement == null) {
            return emptyDashboard2(app, productName, false, branches)
                    .configured(true)
                    .scope("branch")
                    .productId(productId)
                    .productUrl(productUiUrl(productId))
                    .selectedBranch(effectiveBranch)
                    .engagementName(engagementName)
                    .message("Engagement « " + engagementName + " » introuvable pour la branche « " + effectiveBranch + " ».")
                    .engagements(engagements)
                    .build();
        }

        int engagementId = engagement.path("id").asInt();
        Map<String, Integer> bySeverity;
        Map<String, Integer> byTool;
        List<JsonNode> openSample;
        int open;
        int closed = 0;

        Map<String, Integer> byStatus;
        if (filterTag != null) {
            bySeverity = parallelCountBySeverityForTaggedTests(engagementId, filterTag);
            byTool = aggregateToolsFromEngagementWithTag(engagementId, filterTag);
            open = bySeverity.values().stream().mapToInt(Integer::intValue).sum();
            openSample = fetchOpenFindingsSampleForTaggedTests(productId, engagementId, filterTag, 200);
            if (byTool.isEmpty() && !openSample.isEmpty()) {
                byTool = aggregateToolsFromFindings(openSample);
            }
            byStatus = Map.of("active", open, "mitigated", closed);
        } else {
            bySeverity = parallelCountBySeverity(engagementId, null);
            byStatus = parallelCountByStatusLight(engagementId, null);
            open = byStatus.getOrDefault("active", 0);
            closed = byStatus.getOrDefault("mitigated", 0);
            openSample = fetchOpenFindingsSample(productId, engagementId, 50);
            byTool = aggregateToolsFromEngagement(engagementId);
            if (byTool.isEmpty() && !openSample.isEmpty()) {
                byTool = aggregateToolsFromFindings(openSample);
            }
        }

        DefectDojoDashboardCharts charts = buildDashboard2Charts(engagementId, bySeverity);

        return DefectDojoDashboard2Response.builder()
                .configured(true)
                .scope(resolveDashboard2Scope(filterTag, pipelineId, environmentId))
                .environmentTag(environmentId != null ? environmentTag(environmentId) : null)
                .pipelineTag(pipelineId != null ? pipelineTag(pipelineId) : null)
                .applicationName(app.getName())
                .productName(productName)
                .productId(productId)
                .productUrl(productUiUrl(productId))
                .selectedBranch(effectiveBranch)
                .engagementId(engagementId)
                .engagementName(engagementName)
                .bySeverity(bySeverity)
                .byTool(byTool)
                .byStatus(byStatus)
                .totalOpen(open)
                .totalClosed(closed)
                .securityScore(computeSecurityScore(bySeverity))
                .topRecurrent(buildTopRecurrent(openSample, 3))
                .trendPoints(List.of())
                .branches(branches)
                .engagements(engagements)
                .charts(charts)
                .defectDojoBaseUrl(properties.normalizedBaseUrl())
                .build();
    }

    /**
     * Graphiques dashboard2 — branche ou vue globale (produit / toutes branches).
     */
    public DefectDojoDashboardCharts getDashboard2Charts(UUID applicationId, String branch) {
        User user = currentUser();
        AppService app = applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));

        String productName = extractRepoName(app.getGitRepositoryUrl());
        JsonNode product = findProduct(productName);
        if (product == null) {
            return DefectDojoDashboardCharts.builder()
                    .scanSnapshots(List.of())
                    .bySeverity(emptySeverityMap())
                    .build();
        }

        int productId = product.path("id").asInt();

        if (isGlobalBranch(branch)) {
            Map<String, Integer> bySeverity = parallelCountBySeverityForProduct(productId);
            List<DefectDojoEngagementSummary> engagements = listEngagementsForProductLight(productId, productName);
            return buildDashboard2ChartsForGlobal(productId, bySeverity, engagements);
        }

        String effectiveBranch = branch.trim();
        String engagementName = productName + "_" + effectiveBranch;
        JsonNode engagement = findEngagement(productId, engagementName);
        if (engagement == null) {
            return DefectDojoDashboardCharts.builder()
                    .scanSnapshots(List.of())
                    .bySeverity(emptySeverityMap())
                    .build();
        }

        int engagementId = engagement.path("id").asInt();
        Map<String, Integer> bySeverity = parallelCountBySeverity(engagementId, null);
        return buildDashboard2Charts(engagementId, bySeverity);
    }

    public DefectDojoFindingsPageResponse listFindings(
            UUID applicationId,
            String branch,
            String category,
            String severity,
            int page,
            int size,
            String tags,
            String dateFrom,
            String dateTo,
            Integer testId
    ) {
        if (isGlobalBranch(branch)) {
            return listFindingsForProduct(applicationId, category, severity, page, size, tags, dateFrom, dateTo, testId);
        }
        EngagementContext ctx = requireEngagement(applicationId, branch);
        String cat = category != null && !category.isBlank() ? category.trim().toLowerCase() : "open";
        int pageSize = Math.max(1, Math.min(size, 100));
        int offset = Math.max(0, page) * pageSize;

        Map<String, String> params = new LinkedHashMap<>(filtersForCategory(cat));
        params.put("test__engagement", String.valueOf(ctx.engagementId()));
        if (severity != null && !severity.isBlank()) {
            params.put("severity", normalizeSeverity(severity));
        }
        applyTags(params, tags);
        applyDateAndTestFilters(params, dateFrom, dateTo, testId);
        params.put("ordering", orderingForCategory(cat));
        params.put("limit", String.valueOf(pageSize));
        params.put("offset", String.valueOf(offset));

        JsonNode apiPage = get("/api/v2/findings/", params);
        int total = apiPage != null ? apiPage.path("count").asInt(0) : 0;
        Map<Integer, String> testScanTypes = loadTestScanTypesForEngagement(ctx.engagementId());
        List<DefectDojoFindingItem> items = mapFindingPage(apiPage, testScanTypes);
        int totalPages = pageSize > 0 ? (int) Math.ceil(total / (double) pageSize) : 0;

        return DefectDojoFindingsPageResponse.builder()
                .content(items)
                .totalElements(total)
                .totalPages(totalPages)
                .page(page)
                .size(pageSize)
                .category(cat)
                .build();
    }

    public DefectDojoFindingDetailResponse getFindingDetail(UUID applicationId, int findingId, String branch) {
        User user = currentUser();
        AppService app = applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));
        String productName = extractRepoName(app.getGitRepositoryUrl());
        JsonNode product = findProduct(productName);
        if (product == null) {
            throw new IllegalArgumentException("Produit DefectDojo « " + productName + " » introuvable");
        }
        int productId = product.path("id").asInt();

        JsonNode f = get("/api/v2/findings/" + findingId + "/", null);
        if (f == null || !f.has("id")) {
            throw new IllegalArgumentException("Finding DefectDojo introuvable: " + findingId);
        }
        verifyFindingBelongsToProduct(f, productId);

        EngagementContext ctx;
        if (isGlobalBranch(branch)) {
            ctx = engagementContextFromFinding(app, productName, productId, f);
        } else {
            ctx = requireEngagement(applicationId, branch);
            int findingEngagementId = resolveEngagementIdFromFinding(f);
            if (findingEngagementId > 0 && findingEngagementId != ctx.engagementId()) {
                throw new IllegalArgumentException("Ce finding n'appartient pas à l'engagement de la branche sélectionnée");
            }
        }

        JsonNode testDetail = fetchTestDetails(f);
        DefectDojoFindingDetailResponse detail = mapFindingDetail(f, ctx, testDetail);
        enrichFindingCodeContext(detail, app, ctx.branch());
        return detail;
    }

    public enum FindingAction {
        VERIFY, UNVERIFY, FALSE_POSITIVE, OUT_OF_SCOPE, UNDER_REVIEW,
        REACTIVATE, CLOSE, REOPEN, ACCEPT_RISK, UNACCEPT_RISK
    }

    private static Map<String, Object> bodyForAction(FindingAction action) {
        return switch (action) {
            case VERIFY -> Map.of("verified", true, "active", true);
            case UNVERIFY -> Map.of("verified", false);
            case FALSE_POSITIVE -> Map.of("false_p", true, "active", false, "verified", false);
            case OUT_OF_SCOPE -> Map.of("out_of_scope", true, "active", false);
            case UNDER_REVIEW -> Map.of("under_review", true);
            case REACTIVATE -> Map.of(
                    "active", true, "false_p", false, "out_of_scope", false,
                    "is_mitigated", false, "under_review", false, "risk_accepted", false);
            case CLOSE -> Map.of("active", false, "is_mitigated", true);
            case REOPEN -> Map.of("active", true, "is_mitigated", false);
            case ACCEPT_RISK -> Map.of("risk_accepted", true, "active", false);
            case UNACCEPT_RISK -> Map.of("risk_accepted", false, "active", true);
        };
    }

    @CacheEvict(value = "defectDojoDashboard", allEntries = true)
    public DefectDojoFindingDetailResponse updateFindingStatus(
            UUID applicationId,
            int findingId,
            String branch,
            FindingAction action
    ) {
        EngagementContext ctx = requireEngagement(applicationId, branch);
        JsonNode finding = get("/api/v2/findings/" + findingId + "/", Map.of());
        if (finding == null || !finding.has("id")) {
            throw new IllegalArgumentException("Finding introuvable");
        }
        verifyFindingBelongsToProduct(finding, ctx.productId());
        int findingEngagementId = resolveEngagementIdFromFinding(finding);
        if (findingEngagementId > 0 && findingEngagementId != ctx.engagementId()) {
            throw new IllegalArgumentException("Ce finding n'appartient pas à l'engagement de la branche sélectionnée");
        }
        applyFindingAction(findingId, action, finding, ctx);
        return getFindingDetail(applicationId, findingId, branch);
    }

    private void applyFindingAction(int findingId, FindingAction action, JsonNode finding, EngagementContext ctx) {
        if (action == FindingAction.ACCEPT_RISK) {
            applyAcceptRisk(findingId, finding, ctx);
            return;
        }
        patch("/api/v2/findings/" + findingId + "/", bodyForAction(action));
    }

    private void applyAcceptRisk(int findingId, JsonNode finding, EngagementContext ctx) {
        try {
            patchAcceptRisk(findingId);
            return;
        } catch (IllegalStateException patchEx) {
            log.debug("PATCH simple risk accept échoué pour finding {} : {}", findingId, patchEx.getMessage());
        }

        JsonNode product = get("/api/v2/products/" + ctx.productId() + "/", Map.of());
        if (product != null && product.path("enable_full_risk_acceptance").asBoolean(false)) {
            createRiskAcceptance(findingId, finding);
            return;
        }

        throw new IllegalStateException(
                "Acceptation de risque impossible sur ce produit DefectDojo. "
                        + "Activez « Enable Simple Risk Acceptance » (recommandé) ou "
                        + "« Enable Full Risk Acceptance » dans Product → Edit Product.");
    }

    private void patchAcceptRisk(int findingId) {
        patch("/api/v2/findings/" + findingId + "/", bodyForAction(FindingAction.ACCEPT_RISK));
    }

    private void createRiskAcceptance(int findingId, JsonNode finding) {
        int ownerId = resolveApiUserId();
        String title = firstNonBlank(finding.path("title").asText(null), "Finding " + findingId);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("name", truncate("EnviroTest RA #" + findingId, 100));
        body.put("owner", ownerId);
        body.put("recommendation", "A");
        body.put("decision", "A");
        body.put("decision_details", "Accepté via EnviroTest — " + truncate(title, 200));
        body.put("accepted_by", "EnviroTest");
        body.put("accepted_findings", List.of(findingId));
        body.put("expiration_date", Instant.now().plus(90, ChronoUnit.DAYS).toString());
        body.put("reactivate_expired", true);
        post("/api/v2/risk_acceptance/", body);
    }

    /** ID utilisateur DefectDojo lié au token API (requis pour risk_acceptance). */
    private int resolveApiUserId() {
        if (cachedApiUserId != null && cachedApiUserId > 0) {
            return cachedApiUserId;
        }
        JsonNode profile = get("/api/v2/user_profile/", Map.of());
        int userId = profile != null ? profile.path("user").path("id").asInt(0) : 0;
        if (userId <= 0) {
            throw new IllegalStateException(
                    "Impossible d'identifier l'utilisateur DefectDojo (GET /api/v2/user_profile/). "
                            + "Vérifiez que le token API est valide et a les droits Risk Acceptance.");
        }
        cachedApiUserId = userId;
        return userId;
    }

    @CacheEvict(value = "defectDojoDashboard", allEntries = true)
    public void deleteFinding(UUID applicationId, int findingId, String branch) {
        EngagementContext ctx = requireEngagement(applicationId, branch);
        JsonNode finding = get("/api/v2/findings/" + findingId + "/", Map.of());
        if (finding == null || !finding.has("id")) {
            throw new IllegalArgumentException("Finding introuvable");
        }
        verifyFindingBelongsToProduct(finding, ctx.productId());
        int findingEngagementId = resolveEngagementIdFromFinding(finding);
        if (findingEngagementId > 0 && findingEngagementId != ctx.engagementId()) {
            throw new IllegalArgumentException("Ce finding n'appartient pas à l'engagement de la branche sélectionnée");
        }
        delete("/api/v2/findings/" + findingId + "/");
    }

    private void enrichFindingCodeContext(DefectDojoFindingDetailResponse detail, AppService app, String branch) {
        Optional<EphemeralEnvironment> env = findEnvironmentForBranch(currentUser(), app.getId(), branch);

        if (detail.getFilePath() != null && !detail.getFilePath().isBlank()
                && !SourceSnippetFetcherService.isContainerFilesystemPath(detail.getFilePath())) {
            int lineStart = detail.getLine() != null ? detail.getLine() : 0;
            int lineEnd = detail.getLineEnd() != null ? detail.getLineEnd() : lineStart;
            String repoPath = normalizeRepoPath(detail.getFilePath());

            Optional<SourceSnippetFetcherService.CodeSnippetFetch> fetched =
                    sourceSnippetFetcherService.tryFetchSnippetForRepository(app, branch, repoPath, lineStart, lineEnd);
            if (fetched.isEmpty() && env.isPresent()) {
                fetched = sourceSnippetFetcherService.tryFetchSnippet(
                        env.get().getId(), repoPath, lineStart, lineEnd);
            }
            if (fetched.isEmpty() && !repoPath.equals(detail.getFilePath())) {
                fetched = sourceSnippetFetcherService.tryFetchSnippetForRepository(
                        app, branch, detail.getFilePath(), lineStart, lineEnd);
            }
            if (fetched.isPresent()) {
                detail.setCodeSnippet(fetched.get().content());
                detail.setCodeContextSource(fetched.get().source());
                return;
            }
        }

        if (!isContainerImageFinding(detail)) {
            return;
        }

        String imagePath = nullToEmpty(detail.getFilePath());
        detail.setCodeContextHint(
                "Le chemin « " + imagePath + " » est dans l'image conteneur scannée (paquet OS / couche image), "
                        + "pas un fichier de votre dépôt Git.");

        Optional<SourceSnippetFetcherService.CodeSnippetFetch> docker =
                sourceSnippetFetcherService.tryFetchDockerfileFallback(app, branch);
        if (docker.isPresent()) {
            detail.setCodeSnippet(docker.get().content());
            detail.setCodeContextSource(docker.get().source());
            detail.setCodeContextHint(
                    detail.getCodeContextHint()
                            + " Extrait du Dockerfile du dépôt chargé automatiquement pour la remédiation "
                            + "(image de base, version du paquet, etc.).");
        } else {
            detail.setCodeContextHint(
                    detail.getCodeContextHint()
                            + " Aucun Dockerfile trouvé dans le dépôt sur la branche « "
                            + nullToEmpty(branch) + " » — collez-le dans « Affiner l'analyse ».");
        }
    }

    private static boolean isContainerImageFinding(DefectDojoFindingDetailResponse d) {
        String tool = nullToEmpty(d.getToolName()).toLowerCase(Locale.ROOT);
        String scan = nullToEmpty(d.getScanType()).toLowerCase(Locale.ROOT);
        if (tool.contains("grype") || tool.contains("trivy") || scan.contains("container")) {
            return true;
        }
        return SourceSnippetFetcherService.isContainerFilesystemPath(d.getFilePath());
    }

    public String buildAiContext(DefectDojoFindingDetailResponse d) {
        StringBuilder sb = new StringBuilder();
        sb.append("Source: DefectDojo\n");
        sb.append("Produit: ").append(nullToEmpty(d.getProductName())).append("\n");
        sb.append("Engagement (branche): ").append(nullToEmpty(d.getEngagementName())).append("\n");
        sb.append("Titre: ").append(nullToEmpty(d.getTitle())).append("\n");
        sb.append("Sévérité: ").append(nullToEmpty(d.getSeverity())).append("\n");
        sb.append("Outil / scan: ").append(nullToEmpty(d.getToolName())).append(" / ").append(nullToEmpty(d.getScanType())).append("\n");
        if (d.getCve() != null) sb.append("CVE: ").append(d.getCve()).append("\n");
        if (d.getCwe() != null) sb.append("CWE: ").append(d.getCwe()).append("\n");
        if (d.getCvssScore() != null) sb.append("CVSS: ").append(d.getCvssScore()).append("\n");
        sb.append("Fichier: ").append(nullToEmpty(d.getFilePath())).append("\n");
        if (d.getLine() != null) sb.append("Ligne: ").append(d.getLine()).append("\n");
        if (d.getComponentName() != null) sb.append("Composant: ").append(d.getComponentName()).append("\n");
        if ("DOCKERFILE".equalsIgnoreCase(nullToEmpty(d.getCodeContextSource()))) {
            sb.append("Note: finding conteneur — le snippet joint est le Dockerfile du dépôt, pas le chemin image.\n");
        }
        if (d.getCodeContextHint() != null && !d.getCodeContextHint().isBlank()) {
            sb.append("Contexte extrait: ").append(truncateField(d.getCodeContextHint(), 500)).append("\n");
        }
        if (d.getDescription() != null) sb.append("Description scanner:\n").append(truncateField(d.getDescription(), 4000)).append("\n");
        if (d.getMitigation() != null) sb.append("Mitigation DefectDojo:\n").append(truncateField(d.getMitigation(), 2000)).append("\n");
        if (d.getImpact() != null) sb.append("Impact:\n").append(truncateField(d.getImpact(), 2000)).append("\n");
        if (d.getReferences() != null) sb.append("Références:\n").append(truncateField(d.getReferences(), 1000)).append("\n");
        return sb.toString();
    }

    private static String truncateField(String s, int maxChars) {
        if (s == null || s.length() <= maxChars) return s;
        return s.substring(0, maxChars) + "\n[...tronqué]";
    }

    /**
     * Comptage léger des vulnérabilités ouvertes par environnement (tag DefectDojo {@code env-<uuid>}).
     */
    public Map<String, Integer> getEnvironmentOpenCounts(UUID applicationId) {
        User user = currentUser();
        applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));

        if (!properties.isConfigured()) {
            return Map.of();
        }

        AppService app = applicationRepository.findById(applicationId).orElse(null);
        if (app == null) {
            return Map.of();
        }

        String productName = extractRepoName(app.getGitRepositoryUrl());
        JsonNode product = findProduct(productName);
        if (product == null) {
            return Map.of();
        }

        int productId = product.path("id").asInt();
        List<EphemeralEnvironment> envs = environmentRepository
                .findByRequestedByAndServiceIdWithServiceAndPipelineOrderByCreatedAtDesc(user, applicationId)
                .stream()
                .filter(EphemeralEnvironment::isActive)
                .limit(4)
                .toList();

        Map<String, Integer> out = new ConcurrentHashMap<>();
        List<CompletableFuture<Void>> futures = new ArrayList<>();
        for (EphemeralEnvironment env : envs) {
            String envId = env.getId().toString();
            String tag = environmentTag(env.getId());
            futures.add(CompletableFuture.runAsync(() -> {
                int count = countFindingsForProduct(productId, Map.of(
                        "active", "true",
                        "is_mitigated", "false",
                        "duplicate", "false",
                        "test__tags", tag
                ));
                out.put(envId, count);
            }, DD_IO_POOL));
        }
        joinAll(futures);
        Map<String, Integer> ordered = new LinkedHashMap<>();
        for (EphemeralEnvironment env : envs) {
            ordered.put(env.getId().toString(), out.getOrDefault(env.getId().toString(), 0));
        }
        return ordered;
    }

    public static String environmentTag(UUID environmentId) {
        return "env-" + environmentId;
    }

    public static String pipelineTag(Long pipelineId) {
        return pipelineId != null ? "pipeline-" + pipelineId : null;
    }

    private static String resolveDashboard2Scope(String filterTag, Long pipelineId, UUID environmentId) {
        if (filterTag == null) {
            return "branch";
        }
        if (pipelineId != null) {
            return "pipeline";
        }
        if (environmentId != null) {
            return "environment";
        }
        if (SCAN_KIND_TAG.equals(filterTag)) {
            return "scan";
        }
        return "branch";
    }

    private static String resolveDashboardFilterTag(UUID environmentId, Long pipelineId, boolean scanOnly) {
        if (pipelineId != null) {
            return pipelineTag(pipelineId);
        }
        if (environmentId != null) {
            return environmentTag(environmentId);
        }
        if (scanOnly) {
            return SCAN_KIND_TAG;
        }
        return null;
    }

    public List<String> listBranches(UUID applicationId) {
        User user = currentUser();
        applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));

        LinkedHashSet<String> branches = new LinkedHashSet<>();
        for (EphemeralEnvironment env : environmentRepository.findByRequestedByAndServiceIdWithServiceAndPipelineOrderByCreatedAtDesc(user, applicationId)) {
            if (env.getGitBranch() != null && !env.getGitBranch().isBlank()) {
                branches.add(env.getGitBranch().trim());
            }
        }

        AppService app = applicationRepository.findById(applicationId).orElse(null);
        if (app != null && properties.isConfigured()) {
            String productName = extractRepoName(app.getGitRepositoryUrl());
            JsonNode product = findProduct(productName);
            if (product != null) {
                for (DefectDojoEngagementSummary e : listEngagementsForProductLight(product.path("id").asInt(), productName)) {
                    addBranchTag(branches, e, productName);
                }
            }
        }

        if (branches.isEmpty()) {
            branches.add("main");
        }
        return new ArrayList<>(branches);
    }

    private List<String> branchNamesFromEngagements(
            UUID applicationId,
            String productName,
            List<DefectDojoEngagementSummary> engagements
    ) {
        LinkedHashSet<String> branches = new LinkedHashSet<>();
        User user = currentUser();
        for (EphemeralEnvironment env : environmentRepository.findByRequestedByAndServiceIdWithServiceAndPipelineOrderByCreatedAtDesc(user, applicationId)) {
            if (env.getGitBranch() != null && !env.getGitBranch().isBlank()) {
                branches.add(env.getGitBranch().trim());
            }
        }
        for (DefectDojoEngagementSummary e : engagements) {
            addBranchTag(branches, e, productName);
        }
        if (branches.isEmpty()) {
            branches.add("main");
        }
        return new ArrayList<>(branches);
    }

    private static void addBranchTag(LinkedHashSet<String> branches, DefectDojoEngagementSummary e, String productName) {
        if (e.getBranchTag() != null && !e.getBranchTag().isBlank()) {
            branches.add(e.getBranchTag().trim());
        } else if (e.getName() != null && e.getName().startsWith(productName + "_")) {
            branches.add(e.getName().substring(productName.length() + 1));
        }
    }

    private EngagementContext requireEngagement(UUID applicationId, String branch) {
        if (!properties.isConfigured()) {
            throw new IllegalStateException("DefectDojo non configuré");
        }
        User user = currentUser();
        AppService app = applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));
        String productName = extractRepoName(app.getGitRepositoryUrl());
        String effectiveBranch = resolveBranch(applicationId, user, branch);
        String engagementName = productName + "_" + effectiveBranch;

        JsonNode product = findProduct(productName);
        if (product == null) {
            throw new IllegalArgumentException("Produit DefectDojo « " + productName + " » introuvable");
        }
        int productId = product.path("id").asInt();
        JsonNode engagement = findEngagement(productId, engagementName);
        if (engagement == null) {
            throw new IllegalArgumentException("Engagement « " + engagementName + " » introuvable");
        }
        return new EngagementContext(app, productName, effectiveBranch, engagementName, productId, engagement.path("id").asInt());
    }

    private List<DefectDojoMetricCard> buildMetricCards(int engagementId, String tags) {
        return buildMetricCardsParallel(engagementId, tags);
    }

    private List<DefectDojoMetricCard> buildMetricCardsParallel(
            int engagementId,
            String tags,
            CompletableFuture<Map<String, Integer>> openBySeverityFuture
    ) {
        Map<String, Integer> openBySeverity = openBySeverityFuture.join();
        List<String> keys = List.of(
                "verified", "open", "risk_accepted", "closed",
                "false_positive", "out_of_scope", "total", "inactive"
        );
        Map<String, String> labels = Map.of(
                "verified", "Verified Findings",
                "open", "Open Findings",
                "risk_accepted", "Risk Accepted",
                "closed", "Closed Findings",
                "false_positive", "False Positive",
                "out_of_scope", "Out of Scope",
                "total", "Total Findings",
                "inactive", "Inactive Findings"
        );
        List<DefectDojoMetricCard> cards = new ArrayList<>();
        for (String key : keys) {
            if ("open".equals(key)) {
                int openTotal = openBySeverity.values().stream().mapToInt(Integer::intValue).sum();
                cards.add(DefectDojoMetricCard.builder()
                        .key("open")
                        .label(labels.get("open"))
                        .total(openTotal)
                        .bySeverity(new LinkedHashMap<>(openBySeverity))
                        .build());
                continue;
            }
            cards.add(metricCardSequential(key, labels.get(key), engagementId, filtersForCategory(key), tags));
        }
        return cards;
    }

    /** Comptages séquentiels par sévérité — évite deadlock sur DD_IO_POOL. */
    private DefectDojoMetricCard metricCardSequential(
            String key,
            String label,
            int engagementId,
            Map<String, String> baseFilters,
            String tags
    ) {
        Map<String, Integer> orderedBySev = new LinkedHashMap<>();
        int total = 0;
        for (String sev : SEVERITIES) {
            Map<String, String> p = new LinkedHashMap<>(baseFilters);
            p.put("severity", sev);
            int c = countFindings(engagementId, p, tags);
            orderedBySev.put(sev, c);
            total += c;
        }
        if ("total".equals(key)) {
            total = countFindings(engagementId, baseFilters, tags);
        }
        return DefectDojoMetricCard.builder().key(key).label(label).total(total).bySeverity(orderedBySev).build();
    }

    private List<DefectDojoMetricCard> buildMetricCardsParallel(int engagementId, String tags) {
        return buildMetricCardsParallel(engagementId, tags,
                CompletableFuture.completedFuture(emptySeverityMap()));
    }

    private DefectDojoMetricCard metricCard(
            String key,
            String label,
            int engagementId,
            Map<String, String> baseFilters,
            String tags
    ) {
        return metricCardSequential(key, label, engagementId, baseFilters, tags);
    }

    private Map<String, String> filtersForCategory(String category) {
        return switch (category.toLowerCase()) {
            case "open" -> OPEN_FILTERS;
            case "closed" -> Map.of("is_mitigated", "true");
            case "verified" -> Map.of("verified", "true", "active", "true", "is_mitigated", "false");
            case "risk_accepted" -> Map.of("risk_accepted", "true");
            case "false_positive" -> Map.of("false_p", "true");
            case "out_of_scope" -> Map.of("out_of_scope", "true");
            case "inactive" -> Map.of("active", "false");
            case "total" -> Map.of();
            default -> OPEN_FILTERS;
        };
    }

    private String orderingForCategory(String category) {
        return switch (category.toLowerCase()) {
            case "closed" -> "-mitigated,-id";
            default -> "-numerical_severity,-id";
        };
    }

    private static String normalizeSeverity(String severity) {
        if (severity == null || severity.isBlank()) return "Info";
        String s = severity.trim().toLowerCase();
        return switch (s) {
            case "critical" -> "Critical";
            case "high" -> "High";
            case "medium" -> "Medium";
            case "low" -> "Low";
            case "info" -> "Info";
            default -> severity.trim();
        };
    }

    private DefectDojoFindingItem mapFindingItem(JsonNode f) {
        return mapFindingItem(f, null, null);
    }

    private List<DefectDojoFindingItem> mapFindingPage(JsonNode apiPage, Map<Integer, String> testScanTypes) {
        List<DefectDojoFindingItem> items = new ArrayList<>();
        if (apiPage == null || !apiPage.has("results")) {
            return items;
        }
        for (JsonNode f : apiPage.path("results")) {
            items.add(mapFindingItem(f, null, testScanTypes));
        }
        return items;
    }

    private Map<Integer, String> loadTestScanTypesForEngagement(int engagementId) {
        Map<Integer, String> map = new LinkedHashMap<>();
        JsonNode page = get("/api/v2/tests/", Map.of(
                "engagement", String.valueOf(engagementId),
                "limit", "100",
                "ordering", "-id"
        ));
        indexTestScanTypes(page, map);
        return map;
    }

    private Map<Integer, String> loadTestScanTypesForProduct(int productId) {
        Map<Integer, String> map = new LinkedHashMap<>();
        JsonNode page = get("/api/v2/tests/", Map.of(
                "test__engagement__product", String.valueOf(productId),
                "limit", "100",
                "ordering", "-id"
        ));
        indexTestScanTypes(page, map);
        return map;
    }

    private static void indexTestScanTypes(JsonNode page, Map<Integer, String> map) {
        if (page == null || !page.has("results")) {
            return;
        }
        for (JsonNode t : page.path("results")) {
            int id = t.path("id").asInt();
            if (id <= 0) {
                continue;
            }
            String label = resolveScanTypeFromTest(t);
            if (label == null || label.isBlank()) {
                label = t.path("title").asText("Test #" + id);
            }
            map.put(id, label.trim());
        }
    }

    private static int extractTestId(JsonNode f) {
        JsonNode test = f.path("test");
        if (test.isInt() || test.isIntegralNumber()) {
            return test.asInt();
        }
        if (test.isObject()) {
            return test.path("id").asInt();
        }
        return 0;
    }

    private DefectDojoFindingItem mapFindingItem(JsonNode f, JsonNode testDetail, Map<Integer, String> testScanTypes) {
        int id = f.path("id").asInt();
        int testId = extractTestId(f);
        JsonNode test = testDetail != null ? testDetail
                : (f.path("test").isObject() ? f.path("test") : null);
        String scanType = test != null ? resolveScanTypeFromTest(test) : null;
        String testTitle = test != null ? test.path("title").asText(null) : null;
        if ((scanType == null || scanType.isBlank()) && testId > 0 && testScanTypes != null) {
            scanType = testScanTypes.get(testId);
        }
        if (scanType == null || scanType.isBlank()) {
            scanType = inferScannerFromTitle(f.path("title").asText(null));
        }
        if (scanType == null || scanType.isBlank()) {
            scanType = "—";
        }
        return DefectDojoFindingItem.builder()
                .id(id)
                .title(firstNonBlank(f.path("title").asText(null), f.path("description").asText("Sans titre")))
                .description(truncate(f.path("description").asText(null), 500))
                .severity(f.path("severity").asText("Info"))
                .status(buildStatusLabel(f))
                .active(f.path("active").asBoolean(false))
                .verified(f.path("verified").asBoolean(false))
                .mitigated(f.path("is_mitigated").asBoolean(false))
                .falsePositive(f.path("false_p").asBoolean(false))
                .outOfScope(f.path("out_of_scope").asBoolean(false))
                .riskAccepted(f.path("risk_accepted").asBoolean(false))
                .underReview(f.path("under_review").asBoolean(false))
                .cwe(f.path("cwe").asInt(0) > 0 ? "CWE-" + f.path("cwe").asInt() : null)
                .cve(extractCve(f))
                .cvssScore(f.path("cvssv3_score").isNumber() ? f.path("cvssv3_score").asDouble() : null)
                .filePath(f.path("file_path").asText(null))
                .line(f.path("line").isInt() ? f.path("line").asInt() : null)
                .componentName(f.path("component_name").asText(null))
                .scanType(scanType)
                .testId(testId > 0 ? testId : null)
                .testTitle(testTitle)
                .toolName(scanType)
                .mitigation(f.path("mitigation").asText(null))
                .created(f.path("created").asText(null))
                .mitigatedDate(f.path("mitigated").asText(null))
                .url(findingUiUrl(id))
                .build();
    }

    private static String inferScannerFromTitle(String title) {
        if (title == null || title.isBlank()) {
            return null;
        }
        String t = title.toLowerCase(Locale.ROOT);
        if (t.startsWith("semgrep") || t.contains(".security.")) {
            return "Semgrep";
        }
        if (t.contains("gitleaks") || t.contains("secret")) {
            return "Gitleaks";
        }
        if (t.contains("trivy") || t.contains("grype") || t.contains("dockerfile")) {
            return "Container scan";
        }
        return null;
    }

    private DefectDojoFindingItem mapFindingItem(JsonNode f, JsonNode testDetail) {
        return mapFindingItem(f, testDetail, null);
    }

    private DefectDojoFindingDetailResponse mapFindingDetail(JsonNode f, EngagementContext ctx, JsonNode testDetail) {
        Map<Integer, String> testScanTypes = ctx.engagementId() > 0
                ? loadTestScanTypesForEngagement(ctx.engagementId())
                : Map.of();
        DefectDojoFindingItem item = mapFindingItem(f, testDetail, testScanTypes);
        Integer lineEnd = f.path("end_line").isInt()
                ? Integer.valueOf(f.path("end_line").asInt())
                : item.getLine();
        return DefectDojoFindingDetailResponse.builder()
                .id(item.getId())
                .title(item.getTitle())
                .description(f.path("description").asText(null))
                .severity(item.getSeverity())
                .status(item.getStatus())
                .active(item.isActive())
                .verified(item.isVerified())
                .mitigated(item.isMitigated())
                .falsePositive(f.path("false_p").asBoolean(false))
                .outOfScope(f.path("out_of_scope").asBoolean(false))
                .riskAccepted(f.path("risk_accepted").asBoolean(false))
                .cwe(item.getCwe())
                .cve(item.getCve())
                .cvssScore(item.getCvssScore())
                .filePath(item.getFilePath())
                .line(item.getLine())
                .lineEnd(lineEnd)
                .componentName(item.getComponentName())
                .scanType(item.getScanType())
                .testTitle(item.getTestTitle())
                .toolName(item.getToolName())
                .mitigation(item.getMitigation())
                .impact(f.path("impact").asText(null))
                .references(f.path("references").asText(null))
                .created(item.getCreated())
                .mitigatedDate(item.getMitigatedDate())
                .branch(ctx.branch())
                .engagementName(ctx.engagementName())
                .productName(ctx.productName())
                .applicationId(ctx.application().getId())
                .codeContextSource("NONE")
                .build();
    }

    private static String buildStatusLabel(JsonNode f) {
        List<String> parts = new ArrayList<>();
        if (!f.path("active").asBoolean(false)) parts.add("Inactive");
        if (f.path("verified").asBoolean(false)) parts.add("Verified");
        if (f.path("is_mitigated").asBoolean(false)) parts.add("Mitigated");
        if (f.path("false_p").asBoolean(false)) parts.add("False Positive");
        if (f.path("risk_accepted").asBoolean(false)) parts.add("Risk Accepted");
        if (f.path("out_of_scope").asBoolean(false)) parts.add("Out of Scope");
        if (f.path("under_review").asBoolean(false)) parts.add("Under Review");
        return parts.isEmpty() ? "Active" : String.join(", ", parts);
    }

    private static String extractCve(JsonNode f) {
        String cve = f.path("cve").asText(null);
        if (cve != null && !cve.isBlank()) return cve.trim();
        String title = f.path("title").asText("");
        if (title.toUpperCase().startsWith("CVE-")) {
            return title.split("\\s")[0];
        }
        return null;
    }

    private Optional<EphemeralEnvironment> findEnvironmentForBranch(User user, UUID appId, String branch) {
        return environmentRepository
                .findByRequestedByAndServiceIdWithServiceAndPipelineOrderByCreatedAtDesc(user, appId)
                .stream()
                .filter(e -> branch.equals(e.getGitBranch()))
                .findFirst();
    }

    private static String nullToEmpty(String s) {
        return s != null ? s : "";
    }

    private static String truncate(String s, int max) {
        if (s == null) return null;
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    private static String formatDefectDojoApiError(HttpStatusCode status, String body) {
        if (body == null || body.isBlank()) {
            return String.valueOf(status.value());
        }
        String trimmed = body.strip();
        if (trimmed.startsWith("<!DOCTYPE") || trimmed.startsWith("<html") || trimmed.contains("<html")) {
            return status.value()
                    + " — endpoint API introuvable ou page HTML reçue "
                    + "(vérifiez DEFECTDOJO_URL et les droits Risk Acceptance du token API).";
        }
        return status.value() + " — " + truncate(trimmed, 280);
    }

    /** DefectDojo renvoie souvent {@code test} comme ID entier en détail, pas comme objet. */
    private JsonNode fetchTestDetails(JsonNode finding) {
        JsonNode testNode = finding.path("test");
        if (testNode.isObject() && testNode.has("id")) {
            return testNode;
        }
        int testId = testNode.isInt() ? testNode.asInt() : testNode.path("id").asInt(0);
        if (testId <= 0) {
            return null;
        }
        return get("/api/v2/tests/" + testId + "/", null);
    }

    private int resolveEngagementIdFromFinding(JsonNode finding) {
        int direct = extractRelationId(finding, "engagement");
        if (direct > 0) {
            return direct;
        }
        JsonNode test = fetchTestDetails(finding);
        if (test != null) {
            return extractRelationId(test, "engagement");
        }
        return 0;
    }

    private int extractRelationId(JsonNode node, String field) {
        if (node == null || node.isMissingNode()) {
            return 0;
        }
        JsonNode ref = node.path(field);
        if (ref.isInt()) {
            return ref.asInt();
        }
        if (ref.isObject()) {
            return ref.path("id").asInt(0);
        }
        return 0;
    }

    private void verifyFindingBelongsToProduct(JsonNode finding, int expectedProductId) {
        int engagementId = resolveEngagementIdFromFinding(finding);
        if (engagementId <= 0) {
            log.warn("Engagement non résolu pour finding {} — contrôle produit ignoré", finding.path("id").asInt());
            return;
        }
        JsonNode engagement = get("/api/v2/engagements/" + engagementId + "/", null);
        if (engagement == null) {
            throw new IllegalArgumentException("Engagement DefectDojo introuvable pour ce finding");
        }
        int productId = extractRelationId(engagement, "product");
        if (productId != expectedProductId) {
            throw new IllegalArgumentException("Ce finding n'appartient pas au produit de cette application");
        }
    }

    private static String normalizeRepoPath(String filePath) {
        if (filePath == null || filePath.isBlank()) {
            return filePath;
        }
        String p = filePath.trim().replace('\\', '/');
        if (p.startsWith("user-repo/")) {
            p = p.substring("user-repo/".length());
        }
        if (p.startsWith("./")) {
            p = p.substring(2);
        }
        return p;
    }

    private JsonNode findProduct(String productName) {
        if (productName == null || productName.isBlank()) {
            return null;
        }
        JsonNode page = get("/api/v2/products/", Map.of("name", productName, "limit", "25"));
        JsonNode match = matchProductByName(page, productName);
        if (match != null) {
            return match;
        }
        JsonNode all = get("/api/v2/products/", Map.of("limit", "200", "ordering", "name"));
        return matchProductByName(all, productName);
    }

    private static JsonNode matchProductByName(JsonNode page, String productName) {
        if (page == null || !page.has("results")) {
            return null;
        }
        for (JsonNode item : page.path("results")) {
            if (productName.equalsIgnoreCase(item.path("name").asText())) {
                return item;
            }
        }
        return null;
    }

    private String explainMissingProduct(String expectedProductName) {
        String baseUrl = properties.normalizedBaseUrl();
        if (lastApiError != null && !lastApiError.isBlank()) {
            return "Connexion DefectDojo impossible (" + baseUrl + ") : " + lastApiError
                    + ". Vérifiez que DEFECTDOJO_URL du backend est identique à GitLab CI "
                    + "(https://votre-tunnel.trycloudflare.com, sans slash final), redémarrez le backend.";
        }
        JsonNode all = get("/api/v2/products/", Map.of("limit", "50", "ordering", "name"));
        if (all == null) {
            return "DefectDojo ne répond pas à " + baseUrl
                    + ". Vérifiez le tunnel Cloudflare/ngrok, le token API, et redémarrez le backend.";
        }
        List<String> names = new ArrayList<>();
        for (JsonNode item : all.path("results")) {
            names.add(item.path("name").asText());
        }
        if (names.isEmpty()) {
            return "DefectDojo joignable mais aucun produit visible avec ce token."
                    + " Créez un token API pour le compte propriétaire du produit « "
                    + expectedProductName + " ».";
        }
        return "Produit « " + expectedProductName + " » introuvable. Produits API : "
                + String.join(", ", names)
                + " (nom dérivé du dépôt Git).";
    }

    private JsonNode findEngagement(int productId, String engagementName) {
        JsonNode page = get("/api/v2/engagements/", Map.of(
                "product", String.valueOf(productId),
                "name", engagementName,
                "limit", "10"
        ));
        if (page == null) return null;
        for (JsonNode item : page.path("results")) {
            if (engagementName.equalsIgnoreCase(item.path("name").asText())) {
                return item;
            }
        }
        return page.path("results").size() > 0 ? page.path("results").get(0) : null;
    }

    private List<DefectDojoEngagementSummary> listEngagementsForProduct(int productId, String productName) {
        JsonNode page = get("/api/v2/engagements/", Map.of(
                "product", String.valueOf(productId),
                "limit", "100",
                "ordering", "-id"
        ));
        if (page == null) return List.of();

        List<DefectDojoEngagementSummary> out = new ArrayList<>();
        for (JsonNode item : page.path("results")) {
            int id = item.path("id").asInt();
            String name = item.path("name").asText();
            String branchTag = item.path("branch_tag").asText(null);
            if ((branchTag == null || branchTag.isBlank()) && name.startsWith(productName + "_")) {
                branchTag = name.substring(productName.length() + 1);
            }
            out.add(DefectDojoEngagementSummary.builder()
                    .id(id)
                    .name(name)
                    .branchTag(branchTag)
                    .status(item.path("status").asText(null))
                    .activeFindings(countFindings(id, OPEN_FILTERS, null))
                    .url(engagementUiUrl(id))
                    .build());
        }
        return out;
    }

    private List<DefectDojoEngagementSummary> listLocalBranches(UUID applicationId, User user) {
        return environmentRepository.findByRequestedByAndServiceIdWithServiceAndPipelineOrderByCreatedAtDesc(user, applicationId)
                .stream()
                .map(EphemeralEnvironment::getGitBranch)
                .filter(b -> b != null && !b.isBlank())
                .distinct()
                .map(b -> DefectDojoEngagementSummary.builder().branchTag(b).name(b).build())
                .collect(Collectors.toList());
    }

    private Map<String, Integer> countBySeverityParallel(int engagementId, String tags) {
        Map<String, Integer> counts = new ConcurrentHashMap<>();
        List<CompletableFuture<Void>> futures = new ArrayList<>();
        for (String sev : SEVERITIES) {
            futures.add(CompletableFuture.runAsync(() ->
                    counts.put(sev, countFindings(engagementId, openFiltersWithSeverity(sev), tags)), DD_IO_POOL));
        }
        joinAll(futures);
        return orderedSeverityCounts(counts);
    }

    private static Map<String, Integer> orderedSeverityCounts(Map<String, Integer> counts) {
        Map<String, Integer> ordered = new LinkedHashMap<>();
        for (String sev : SEVERITIES) {
            ordered.put(sev, counts.getOrDefault(sev, 0));
        }
        return ordered;
    }

    private Map<String, Integer> countBySeverity(int engagementId, String tags) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String sev : SEVERITIES) {
            counts.put(sev, countFindings(engagementId, openFiltersWithSeverity(sev), tags));
        }
        return counts;
    }

    private Map<String, Integer> countByStatus(int engagementId, String tags) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        counts.put("active", countFindings(engagementId, OPEN_FILTERS, tags));
        counts.put("mitigated", countFindings(engagementId, Map.of("is_mitigated", "true"), tags));
        counts.put("verified", countFindings(engagementId, Map.of(
                "verified", "true", "active", "true", "is_mitigated", "false"), tags));
        counts.put("falsePositive", countFindings(engagementId, Map.of("false_p", "true"), tags));
        counts.put("duplicate", countFindings(engagementId, Map.of("duplicate", "true"), tags));
        return counts;
    }

    private Map<String, Integer> parallelCountBySeverity(int engagementId, String tags) {
        return countBySeverityParallel(engagementId, tags);
    }

    /** Comptages actif/mitigé uniquement — suffisant pour dashboard2. */
    private Map<String, Integer> parallelCountByStatusLight(int engagementId, String tags) {
        Map<String, Integer> counts = new ConcurrentHashMap<>();
        List<CompletableFuture<Void>> futures = List.of(
                CompletableFuture.runAsync(() -> counts.put("active", countFindings(engagementId, OPEN_FILTERS, tags)), DD_IO_POOL),
                CompletableFuture.runAsync(() -> counts.put("mitigated", countFindings(engagementId, Map.of(
                        "is_mitigated", "true"), tags)), DD_IO_POOL)
        );
        joinAll(futures);
        Map<String, Integer> ordered = new LinkedHashMap<>();
        ordered.put("active", counts.getOrDefault("active", 0));
        ordered.put("mitigated", counts.getOrDefault("mitigated", 0));
        return ordered;
    }

    /** Comptages par sévérité au niveau produit — alignés sur OPEN_FILTERS. */
    private Map<String, Integer> parallelCountBySeverityForProduct(int productId) {
        Map<String, Integer> counts = new ConcurrentHashMap<>();
        List<CompletableFuture<Void>> futures = new ArrayList<>();
        for (String sev : SEVERITIES) {
            futures.add(CompletableFuture.runAsync(() -> counts.put(sev, countFindingsForProduct(productId,
                    openFiltersWithSeverity(sev))), DD_IO_POOL));
        }
        joinAll(futures);
        return orderedSeverityCounts(counts);
    }

    private Map<String, Integer> parallelCountByStatusLightForProduct(int productId) {
        Map<String, Integer> counts = new ConcurrentHashMap<>();
        List<CompletableFuture<Void>> futures = List.of(
                CompletableFuture.runAsync(() -> counts.put("active", countFindingsForProduct(productId, OPEN_FILTERS)), DD_IO_POOL),
                CompletableFuture.runAsync(() -> counts.put("mitigated", countFindingsForProduct(productId, Map.of(
                        "is_mitigated", "true"))), DD_IO_POOL)
        );
        joinAll(futures);
        Map<String, Integer> ordered = new LinkedHashMap<>();
        ordered.put("active", counts.getOrDefault("active", 0));
        ordered.put("mitigated", counts.getOrDefault("mitigated", 0));
        return ordered;
    }

    private Map<String, Integer> parallelCountByStatus(int engagementId, String tags) {
        Map<String, Integer> counts = new ConcurrentHashMap<>();
        List<CompletableFuture<Void>> futures = List.of(
                CompletableFuture.runAsync(() -> counts.put("active", countFindings(engagementId, OPEN_FILTERS, tags)), DD_IO_POOL),
                CompletableFuture.runAsync(() -> counts.put("mitigated", countFindings(engagementId, Map.of(
                        "is_mitigated", "true"), tags)), DD_IO_POOL),
                CompletableFuture.runAsync(() -> counts.put("verified", countFindings(engagementId, Map.of(
                        "verified", "true", "active", "true", "is_mitigated", "false"), tags)), DD_IO_POOL),
                CompletableFuture.runAsync(() -> counts.put("falsePositive", countFindings(engagementId, Map.of(
                        "false_p", "true"), tags)), DD_IO_POOL),
                CompletableFuture.runAsync(() -> counts.put("duplicate", countFindings(engagementId, Map.of(
                        "duplicate", "true"), tags)), DD_IO_POOL)
        );
        joinAll(futures);
        Map<String, Integer> ordered = new LinkedHashMap<>();
        ordered.put("active", counts.getOrDefault("active", 0));
        ordered.put("mitigated", counts.getOrDefault("mitigated", 0));
        ordered.put("verified", counts.getOrDefault("verified", 0));
        ordered.put("falsePositive", counts.getOrDefault("falsePositive", 0));
        ordered.put("duplicate", counts.getOrDefault("duplicate", 0));
        return ordered;
    }

    private static void joinAllFutures(List<? extends CompletableFuture<?>> futures) {
        if (futures == null || futures.isEmpty()) {
            return;
        }
        CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new)).join();
    }

    private static void joinAll(List<CompletableFuture<Void>> futures) {
        if (futures.isEmpty()) {
            return;
        }
        CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new)).join();
    }

    private int countFindings(int engagementId, Map<String, String> extraParams, String tags) {
        Map<String, String> params = new LinkedHashMap<>(extraParams);
        params.put("test__engagement", String.valueOf(engagementId));
        applyTags(params, tags);
        params.put("limit", "1");
        JsonNode page = get("/api/v2/findings/", params);
        return page != null ? page.path("count").asInt(0) : 0;
    }

    private static void applyTags(Map<String, String> params, String tags) {
        if (tags == null || tags.isBlank()) {
            return;
        }
        String trimmed = tags.trim();
        // Import CI : tags env-*, pipeline-*, scan, deploy sont posés sur le Test DefectDojo.
        if (trimmed.startsWith("env-") || trimmed.startsWith("pipeline-")
                || SCAN_KIND_TAG.equals(trimmed) || DEPLOY_KIND_TAG.equals(trimmed)) {
            params.put("test__tags", trimmed);
        } else {
            params.put("tags", trimmed);
        }
    }

    private int countFindingsForTest(int testId, Map<String, String> extraParams) {
        Map<String, String> params = new LinkedHashMap<>(extraParams);
        params.put("test", String.valueOf(testId));
        params.put("limit", "1");
        JsonNode page = get("/api/v2/findings/", params);
        return page != null ? page.path("count").asInt(0) : 0;
    }

    private Map<String, Integer> countBySeverityForTest(int testId, boolean openOnly) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String sev : SEVERITIES) {
            Map<String, String> params = new LinkedHashMap<>(Map.of("severity", sev));
            if (openOnly) {
                params.putAll(OPEN_FILTERS);
            }
            counts.put(sev, countFindingsForTest(testId, params));
        }
        return counts;
    }

    private List<JsonNode> fetchAllEngagementFindings(int engagementId) {
        int pageSize = 200;
        int maxPages = 25;
        JsonNode firstPage = fetchEngagementFindingsPage(engagementId, 0, pageSize);
        if (firstPage == null || !firstPage.has("results")) {
            return List.of();
        }
        int total = firstPage.path("count").asInt(0);
        List<JsonNode> all = new ArrayList<>();
        for (JsonNode f : firstPage.path("results")) {
            all.add(f);
        }
        if (all.size() >= total) {
            return all;
        }

        List<CompletableFuture<List<JsonNode>>> pageFutures = new ArrayList<>();
        for (int page = 1, offset = pageSize; offset < total && page < maxPages; page++, offset += pageSize) {
            final int pageOffset = offset;
            pageFutures.add(CompletableFuture.supplyAsync(
                    () -> pageResults(fetchEngagementFindingsPage(engagementId, pageOffset, pageSize)),
                    DD_IO_POOL));
        }
        if (!pageFutures.isEmpty()) {
            joinAllFutures(pageFutures);
            for (CompletableFuture<List<JsonNode>> future : pageFutures) {
                all.addAll(future.join());
            }
        }
        return all;
    }

    private static List<JsonNode> pageResults(JsonNode page) {
        if (page == null || !page.has("results")) {
            return List.of();
        }
        List<JsonNode> out = new ArrayList<>();
        for (JsonNode f : page.path("results")) {
            out.add(f);
        }
        return out;
    }

    private JsonNode fetchEngagementFindingsPage(int engagementId, int offset, int limit) {
        return get("/api/v2/findings/", Map.of(
                "test__engagement", String.valueOf(engagementId),
                "limit", String.valueOf(limit),
                "offset", String.valueOf(offset),
                "ordering", "created"
        ));
    }

    private DefectDojoDashboardCharts buildCharts(
            int engagementId,
            Map<String, Integer> bySeverityOpen,
            Map<String, Integer> byStatus,
            int openCount,
            int closedCount,
            String tags
    ) {
        List<JsonNode> timelineFindings = fetchAllEngagementFindings(engagementId);
        List<JsonNode> findings = filterCurrentlyOpenFindings(timelineFindings);
        List<DefectDojoScanSnapshot> scanSnapshots = buildScanSnapshotsFast(engagementId);
        return buildChartsFromParts(bySeverityOpen, byStatus, openCount, closedCount, findings, timelineFindings, scanSnapshots);
    }

    private DefectDojoDashboardCharts buildChartsFromParts(
            Map<String, Integer> bySeverityOpen,
            Map<String, Integer> byStatus,
            int openCount,
            int closedCount,
            List<JsonNode> findings,
            List<JsonNode> timelineFindings,
            List<DefectDojoScanSnapshot> scanSnapshotsRaw
    ) {
        Map<String, Integer> byTool = new LinkedHashMap<>();
        Map<String, Integer> byAnalysisType = new LinkedHashMap<>();

        for (JsonNode f : findings) {
            if (!isCurrentlyOpen(f)) {
                continue;
            }
            String scanType = resolveScanTypeFromFinding(f);
            byTool.merge(scanType, 1, Integer::sum);
            byAnalysisType.merge(classifyAnalysisType(scanType), 1, Integer::sum);
        }

        List<DefectDojoScanSnapshot> scanSnapshots = scanSnapshotsRaw != null ? scanSnapshotsRaw : List.of();
        DefectDojoDetailedMetrics detailedMetrics = buildDetailedMetrics(
                findings,
                timelineFindings != null ? timelineFindings : findings,
                scanSnapshots);

        String lastScanDate = scanSnapshots.isEmpty() ? null
                : scanSnapshots.get(scanSnapshots.size() - 1).getDate();

        return DefectDojoDashboardCharts.builder()
                .openCount(openCount)
                .closedCount(closedCount)
                .totalCount(openCount + closedCount)
                .bySeverity(bySeverityOpen)
                .byTool(byTool)
                .byAnalysisType(byAnalysisType)
                .byStatus(byStatus)
                .scanSnapshots(scanSnapshots)
                .detailedMetrics(detailedMetrics)
                .lastScanDate(lastScanDate)
                .build();
    }

    private DefectDojoDetailedMetrics buildDetailedMetrics(
            List<JsonNode> findings,
            List<JsonNode> timelineFindings,
            List<DefectDojoScanSnapshot> scanSnapshots
    ) {
        List<JsonNode> valid = findings.stream()
                .filter(f -> !f.path("duplicate").asBoolean(false))
                .toList();

        List<DefectDojoScanSnapshot> sortedScans = new ArrayList<>(scanSnapshots);
        sortedScans.sort(Comparator.comparing(
                DefectDojoScanSnapshot::getTimestamp,
                Comparator.nullsLast(String::compareTo)
        ));

        List<DefectDojoTimeSeriesPoint> openDayToDay = buildOpenDayToDayFromFindings(timelineFindings);
        List<DefectDojoTimeSeriesPoint> openHourToHour = new ArrayList<>();
        for (DefectDojoScanSnapshot snap : sortedScans) {
            String hour = extractHour(snap.getTimestamp());
            if (hour != null) {
                openHourToHour.add(DefectDojoTimeSeriesPoint.builder()
                        .period(hour)
                        .bySeverity(snap.getBySeverity())
                        .build());
            }
        }

        Map<String, Map<String, Integer>> weekSeverityAgg = new TreeMap<>();
        Map<String, int[]> weekCounts = new TreeMap<>();
        for (int i = 0; i < sortedScans.size(); i++) {
            DefectDojoScanSnapshot snap = sortedScans.get(i);
            String ts = firstNonBlank(snap.getTimestamp(), snap.getDate());
            String weekKey = toWeekKey(ts);
            if (weekKey == null) {
                continue;
            }
            weekSeverityAgg.merge(weekKey, snap.getBySeverity(), DefectDojoService::mergeSeverityMaps);

            if (i == 0) {
                weekCounts.computeIfAbsent(weekKey, k -> new int[3])[0] += snap.getTotalOpen();
            } else {
                int diff = snap.getTotalOpen() - sortedScans.get(i - 1).getTotalOpen();
                if (diff > 0) {
                    weekCounts.computeIfAbsent(weekKey, k -> new int[3])[0] += diff;
                } else if (diff < 0) {
                    weekCounts.computeIfAbsent(weekKey, k -> new int[3])[1] += -diff;
                }
            }
        }
        for (JsonNode f : valid) {
            if (f.path("risk_accepted").asBoolean(false)) {
                String raWeek = toWeekKey(f.path("created").asText(null));
                if (raWeek != null) {
                    weekCounts.computeIfAbsent(raWeek, k -> new int[3])[2]++;
                }
            }
        }

        List<DefectDojoWeekStatusPoint> weekStatus = new ArrayList<>();
        for (Map.Entry<String, int[]> e : weekCounts.entrySet()) {
            weekStatus.add(DefectDojoWeekStatusPoint.builder()
                    .week(formatWeekLabel(e.getKey()))
                    .opened(e.getValue()[0])
                    .closed(e.getValue()[1])
                    .riskAccepted(e.getValue()[2])
                    .build());
        }

        List<DefectDojoTimeSeriesPoint> weekToWeekBySeverity = new ArrayList<>();
        for (Map.Entry<String, Map<String, Integer>> e : weekSeverityAgg.entrySet()) {
            weekToWeekBySeverity.add(DefectDojoTimeSeriesPoint.builder()
                    .period(formatWeekLabel(e.getKey()))
                    .bySeverity(e.getValue())
                    .build());
        }

        Map<String, Integer> ageBuckets = new LinkedHashMap<>();
        ageBuckets.put("0-7 j", 0);
        ageBuckets.put("8-30 j", 0);
        ageBuckets.put("31-90 j", 0);
        ageBuckets.put("91+ j", 0);
        int openForAge = 0;
        java.time.LocalDate today = java.time.LocalDate.now();
        for (JsonNode f : valid) {
            if (!isCurrentlyOpen(f)) {
                continue;
            }
            openForAge++;
            java.time.LocalDate created = parseLocalDate(f.path("created").asText(null));
            if (created == null) {
                ageBuckets.merge("0-7 j", 1, Integer::sum);
                continue;
            }
            long days = java.time.temporal.ChronoUnit.DAYS.between(created, today);
            if (days <= 7) {
                ageBuckets.merge("0-7 j", 1, Integer::sum);
            } else if (days <= 30) {
                ageBuckets.merge("8-30 j", 1, Integer::sum);
            } else if (days <= 90) {
                ageBuckets.merge("31-90 j", 1, Integer::sum);
            } else {
                ageBuckets.merge("91+ j", 1, Integer::sum);
            }
        }

        Map<String, Map<Integer, Integer>> activityMatrix = new TreeMap<>();
        String[] dayLabels = {"Dim", "Lun", "Mar", "Mer", "Jeu", "Ven", "Sam"};
        for (DefectDojoScanSnapshot snap : sortedScans) {
            String ts = firstNonBlank(snap.getTimestamp(), snap.getDate());
            if (ts == null || ts.isBlank()) {
                continue;
            }
            String weekKey = toWeekKey(ts);
            if (weekKey == null) {
                continue;
            }
            java.time.LocalDate d = parseLocalDate(ts);
            if (d == null) {
                continue;
            }
            int dow = d.getDayOfWeek().getValue() % 7;
            activityMatrix.computeIfAbsent(weekKey, k -> new HashMap<>())
                    .merge(dow, 1, Integer::sum);
        }
        List<DefectDojoWeeklyActivityPoint> weeklyActivity = new ArrayList<>();
        for (Map.Entry<String, Map<Integer, Integer>> weekEntry : activityMatrix.entrySet()) {
            String weekLabel = formatWeekLabel(weekEntry.getKey());
            for (Map.Entry<Integer, Integer> dayEntry : weekEntry.getValue().entrySet()) {
                int dow = dayEntry.getKey();
                weeklyActivity.add(DefectDojoWeeklyActivityPoint.builder()
                        .week(weekLabel)
                        .dayOfWeek(dow)
                        .dayLabel(dayLabels[dow])
                        .count(dayEntry.getValue())
                        .build());
            }
        }

        Map<String, Integer> openCwe = new LinkedHashMap<>();
        Map<String, Integer> totalCwe = new LinkedHashMap<>();
        for (JsonNode f : valid) {
            String cwe = formatCwe(f);
            if (cwe == null) {
                continue;
            }
            totalCwe.merge(cwe, 1, Integer::sum);
            if (isCurrentlyOpen(f)) {
                openCwe.merge(cwe, 1, Integer::sum);
            }
        }

        return DefectDojoDetailedMetrics.builder()
                .openDayToDayBySeverity(openDayToDay)
                .openHourToHourBySeverity(openHourToHour)
                .weekToWeekStatus(weekStatus)
                .weekToWeekBySeverity(weekToWeekBySeverity)
                .findingAgeBuckets(ageBuckets)
                .openFindingsForAge(openForAge)
                .weeklyActivity(weeklyActivity)
                .openCwe(topN(openCwe, 12))
                .totalCwe(topN(totalCwe, 20))
                .build();
    }

    private static Map<String, Integer> mergeSeverityMaps(Map<String, Integer> a, Map<String, Integer> b) {
        Map<String, Integer> merged = new LinkedHashMap<>(emptySeverityMap());
        if (a != null) {
            a.forEach((k, v) -> merged.merge(k, v, Integer::sum));
        }
        if (b != null) {
            b.forEach((k, v) -> merged.merge(k, v, Integer::sum));
        }
        return merged;
    }

    private static boolean isCurrentlyOpen(JsonNode f) {
        return isOpenAt(f, java.time.Instant.now().toString());
    }

    private static boolean isOpenAt(JsonNode f, String asOfTimestamp) {
        if (f.path("duplicate").asBoolean(false)) {
            return false;
        }
        if (f.path("false_p").asBoolean(false) || f.path("out_of_scope").asBoolean(false)) {
            return false;
        }
        String created = f.path("created").asText(null);
        if (created == null || created.isBlank() || created.compareTo(asOfTimestamp) > 0) {
            return false;
        }
        if (f.path("is_mitigated").asBoolean(false)) {
            String mitigated = f.path("mitigated").asText(null);
            if (mitigated != null && !mitigated.isBlank() && mitigated.compareTo(asOfTimestamp) <= 0) {
                return false;
            }
        }
        return f.path("active").asBoolean(true);
    }

    private static String formatCwe(JsonNode f) {
        int cwe = f.path("cwe").asInt(0);
        return cwe > 0 ? "CWE-" + cwe : null;
    }

    private static java.time.LocalDate parseLocalDate(String iso) {
        if (iso == null || iso.length() < 10) {
            return null;
        }
        try {
            return java.time.LocalDate.parse(iso.substring(0, 10));
        } catch (Exception e) {
            return null;
        }
    }

    private static String toWeekKey(String isoDateTime) {
        java.time.LocalDate d = parseLocalDate(isoDateTime);
        if (d == null) {
            return null;
        }
        java.time.LocalDate monday = d.with(java.time.DayOfWeek.MONDAY);
        return monday.toString();
    }

    private static String formatWeekLabel(String weekKey) {
        java.time.LocalDate d = parseLocalDate(weekKey);
        if (d == null) {
            return weekKey;
        }
        return d.format(java.time.format.DateTimeFormatter.ofPattern("MM/dd/yyyy"));
    }

    private static Map<String, Integer> topN(Map<String, Integer> source, int n) {
        return source.entrySet().stream()
                .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                .limit(n)
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (a, b) -> a,
                        LinkedHashMap::new
                ));
    }

    private List<DefectDojoScanSnapshot> buildScanSnapshots(int engagementId) {
        JsonNode page = get("/api/v2/tests/", Map.of(
                "engagement", String.valueOf(engagementId),
                "limit", "50",
                "ordering", "created"
        ));
        if (page == null) return List.of();

        List<DefectDojoScanSnapshot> out = new ArrayList<>();
        for (JsonNode t : page.path("results")) {
            int testId = t.path("id").asInt();
            Map<String, Integer> bySev = countBySeverityForTest(testId, true);
            int total = bySev.values().stream().mapToInt(Integer::intValue).sum();
            String scanType = resolveScanTypeFromTest(t);
            if (scanType == null) {
                scanType = "Unknown";
            }
            String timestamp = firstNonBlank(
                    t.path("created").asText(null),
                    t.path("updated").asText(null)
            );
            String date = extractDay(timestamp);
            String label = date != null ? scanType + " · " + date : scanType;
            out.add(DefectDojoScanSnapshot.builder()
                    .testId(testId)
                    .scanType(scanType)
                    .label(label)
                    .date(date)
                    .timestamp(timestamp)
                    .totalOpen(total)
                    .bySeverity(bySev)
                    .build());
        }
        return out;
    }

    private static String resolveScanTypeFromFinding(JsonNode f) {
        JsonNode test = f.path("test");
        if (test.isObject()) {
            String fromTest = resolveScanTypeFromTest(test);
            if (fromTest != null) {
                return fromTest;
            }
        }
        JsonNode foundBy = f.path("found_by");
        if (foundBy.isArray() && !foundBy.isEmpty()) {
            return foundBy.get(0).asText("Unknown");
        }
        return foundBy.asText("Unknown");
    }

    /** DefectDojo expose le nom du scanner via test_type_name (pas scan_type sur /tests/). */
    private static String resolveScanTypeFromTest(JsonNode t) {
        if (t == null || t.isMissingNode()) {
            return null;
        }
        String name = t.path("test_type_name").asText(null);
        if (name != null && !name.isBlank()) {
            return name.trim();
        }
        name = t.path("test_type").path("name").asText(null);
        if (name != null && !name.isBlank()) {
            return name.trim();
        }
        name = t.path("scan_type").asText(null);
        if (name != null && !name.isBlank()) {
            return name.trim();
        }
        name = t.path("title").asText(null);
        if (name != null && !name.isBlank()) {
            return name.trim();
        }
        return null;
    }

    private static String classifyAnalysisType(String scanType) {
        if (scanType == null) return "Autre";
        String s = scanType.toLowerCase();
        if (s.contains("trivy") && s.contains("container")) return "Container";
        if (s.contains("trivy") || s.contains("npm") || s.contains("pip") || s.contains("dependency") || s.contains("safety")) {
            return "SCA";
        }
        if (s.contains("semgrep") || s.contains("eslint") || s.contains("bandit") || s.contains("sast")) return "SAST";
        if (s.contains("gitleaks") || s.contains("secret") || s.contains("truffle")) return "Secrets";
        if (s.contains("checkov") || s.contains("tfsec") || s.contains("iac")) return "IaC";
        if (s.contains("zap") || s.contains("dast") || s.contains("burp")) return "DAST";
        return "Autre";
    }

    private static String extractDay(String isoDateTime) {
        if (isoDateTime == null || isoDateTime.isBlank()) return null;
        return isoDateTime.length() >= 10 ? isoDateTime.substring(0, 10) : isoDateTime;
    }

    private static String extractHour(String isoDateTime) {
        if (isoDateTime == null || isoDateTime.isBlank()) {
            return null;
        }
        if (isoDateTime.length() >= 13 && isoDateTime.charAt(10) == 'T') {
            return isoDateTime.substring(0, 13);
        }
        try {
            java.time.OffsetDateTime odt = java.time.OffsetDateTime.parse(isoDateTime);
            return odt.format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH"));
        } catch (Exception ignored) {
            try {
                java.time.LocalDateTime ldt = java.time.LocalDateTime.parse(isoDateTime);
                return ldt.format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH"));
            } catch (Exception e) {
                return null;
            }
        }
    }

    private DefectDojoDeployRecommendation buildRecommendation(int critical, int high) {
        int threshold = properties.getCriticalThreshold();
        boolean ok = critical <= threshold;
        String status = ok ? "RECOMMANDE" : "NON_RECOMMANDE";
        String reason = ok
                ? "Quality gate PASSED : " + critical + " vulnérabilité(s) critique(s) (seuil ≤ " + threshold + ")."
                : "Quality gate FAILED : " + critical + " vulnérabilité(s) critique(s) (seuil " + threshold + "). Déploiement non recommandé.";
        return DefectDojoDeployRecommendation.builder()
                .status(status)
                .deployRecommended(ok)
                .criticalCount(critical)
                .highCount(high)
                .criticalThreshold(threshold)
                .reason(reason)
                .source("defectdojo-engagement + CRITICAL_THRESHOLD pipeline")
                .build();
    }

    private JsonNode get(String path, Map<String, String> queryParams) {
        lastApiError = null;
        try {
            UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(properties.normalizedBaseUrl() + path);
            if (queryParams != null) {
                queryParams.forEach((k, v) -> {
                    if (v != null && !v.isBlank()) {
                        builder.queryParam(k, v);
                    }
                });
            }

            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            headers.set("Authorization", properties.authorizationHeaderValue());
            headers.set("User-Agent", "EnviroTest-Backend/1.0");
            if (properties.normalizedBaseUrl().contains("ngrok")
                    || properties.normalizedBaseUrl().contains("trycloudflare.com")
                    || properties.normalizedBaseUrl().contains("cloudflare")) {
                headers.set("Ngrok-Skip-Browser-Warning", "true");
            }

            RestTemplate rest = httpClientFactory.create(properties.isInsecureSsl());
            var uri = builder.build(true).toUri();
            ResponseEntity<JsonNode> resp = rest.exchange(
                    uri,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    JsonNode.class
            );
            return resp.getBody();
        } catch (HttpStatusCodeException e) {
            lastApiError = e.getStatusCode() + " — " + truncate(e.getResponseBodyAsString(), 200);
            log.warn("DefectDojo API {} → {} (host={}) : {}", path, e.getStatusCode(),
                    properties.hostForLog(), e.getResponseBodyAsString());
            return null;
        } catch (Exception e) {
            lastApiError = e.getMessage();
            log.warn("DefectDojo API {} error (host={}, url={}): {} — "
                            + "Vérifiez DEFECTDOJO_URL backend = même URL que GitLab CI (tunnel Cloudflare https://...)",
                    path, properties.hostForLog(), properties.normalizedBaseUrl(), e.getMessage());
            return null;
        }
    }

    private JsonNode patch(String path, Map<String, Object> body) {
        try {
            var builder = UriComponentsBuilder.fromHttpUrl(properties.normalizedBaseUrl() + path);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            headers.set("Authorization", properties.authorizationHeaderValue());
            headers.set("User-Agent", "EnviroTest-Backend/1.0");
            if (properties.normalizedBaseUrl().contains("ngrok")
                    || properties.normalizedBaseUrl().contains("trycloudflare.com")
                    || properties.normalizedBaseUrl().contains("cloudflare")) {
                headers.set("Ngrok-Skip-Browser-Warning", "true");
            }
            RestTemplate rest = httpClientFactory.create(properties.isInsecureSsl());
            ResponseEntity<JsonNode> resp = rest.exchange(
                    builder.build(true).toUri(),
                    HttpMethod.PATCH,
                    new HttpEntity<>(body, headers),
                    JsonNode.class);
            return resp.getBody();
        } catch (HttpStatusCodeException e) {
            lastApiError = e.getStatusCode() + " — " + truncate(e.getResponseBodyAsString(), 200);
            log.warn("DefectDojo PATCH {} → {} : {}", path, e.getStatusCode(), e.getResponseBodyAsString());
            throw new IllegalStateException("DefectDojo a refusé la mise à jour : "
                    + formatDefectDojoApiError(e.getStatusCode(), e.getResponseBodyAsString()));
        } catch (Exception e) {
            lastApiError = e.getMessage();
            log.warn("DefectDojo PATCH {} error: {}", path, e.getMessage());
            throw new IllegalStateException("DefectDojo a refusé la mise à jour : " + e.getMessage());
        }
    }

    private JsonNode post(String path, Map<String, Object> body) {
        try {
            var builder = UriComponentsBuilder.fromHttpUrl(properties.normalizedBaseUrl() + path);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            headers.set("Authorization", properties.authorizationHeaderValue());
            headers.set("User-Agent", "EnviroTest-Backend/1.0");
            if (properties.normalizedBaseUrl().contains("ngrok")
                    || properties.normalizedBaseUrl().contains("trycloudflare.com")
                    || properties.normalizedBaseUrl().contains("cloudflare")) {
                headers.set("Ngrok-Skip-Browser-Warning", "true");
            }
            RestTemplate rest = httpClientFactory.create(properties.isInsecureSsl());
            ResponseEntity<JsonNode> resp = rest.exchange(
                    builder.build(true).toUri(),
                    HttpMethod.POST,
                    new HttpEntity<>(body, headers),
                    JsonNode.class);
            return resp.getBody();
        } catch (HttpStatusCodeException e) {
            lastApiError = e.getStatusCode() + " — " + truncate(e.getResponseBodyAsString(), 200);
            log.warn("DefectDojo POST {} → {} : {}", path, e.getStatusCode(), e.getResponseBodyAsString());
            throw new IllegalStateException("DefectDojo a refusé l'opération : "
                    + formatDefectDojoApiError(e.getStatusCode(), e.getResponseBodyAsString()));
        } catch (Exception e) {
            lastApiError = e.getMessage();
            log.warn("DefectDojo POST {} error: {}", path, e.getMessage());
            throw new IllegalStateException("DefectDojo a refusé l'opération : " + e.getMessage());
        }
    }

    private void delete(String path) {
        try {
            var builder = UriComponentsBuilder.fromHttpUrl(properties.normalizedBaseUrl() + path);
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            headers.set("Authorization", properties.authorizationHeaderValue());
            headers.set("User-Agent", "EnviroTest-Backend/1.0");
            if (properties.normalizedBaseUrl().contains("ngrok")
                    || properties.normalizedBaseUrl().contains("trycloudflare.com")
                    || properties.normalizedBaseUrl().contains("cloudflare")) {
                headers.set("Ngrok-Skip-Browser-Warning", "true");
            }
            RestTemplate rest = httpClientFactory.create(properties.isInsecureSsl());
            rest.exchange(
                    builder.build(true).toUri(),
                    HttpMethod.DELETE,
                    new HttpEntity<>(headers),
                    Void.class);
        } catch (HttpStatusCodeException e) {
            lastApiError = e.getStatusCode() + " — " + truncate(e.getResponseBodyAsString(), 200);
            log.warn("DefectDojo DELETE {} → {} : {}", path, e.getStatusCode(), e.getResponseBodyAsString());
            throw new IllegalStateException("DefectDojo a refusé la suppression : " + e.getStatusCode());
        } catch (Exception e) {
            lastApiError = e.getMessage();
            log.warn("DefectDojo DELETE {} error: {}", path, e.getMessage());
            throw new IllegalStateException("DefectDojo a refusé la suppression : " + e.getMessage());
        }
    }

    private static void applyDateAndTestFilters(
            Map<String, String> params,
            String dateFrom,
            String dateTo,
            Integer testId
    ) {
        if (dateFrom != null && !dateFrom.isBlank()) {
            params.put("date__gte", dateFrom.trim());
        }
        if (dateTo != null && !dateTo.isBlank()) {
            params.put("date__lte", dateTo.trim());
        }
        if (testId != null) {
            params.put("test", String.valueOf(testId));
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    static String extractRepoName(String gitUrl) {
        if (gitUrl == null || gitUrl.isBlank()) {
            return "unknown";
        }
        String s = gitUrl.trim();
        s = s.replaceAll("\\.git$", "");
        int slash = s.lastIndexOf('/');
        return slash >= 0 ? s.substring(slash + 1) : s;
    }

    private String resolveBranch(UUID applicationId, User user, String requestedBranch) {
        if (requestedBranch != null && !requestedBranch.isBlank()) {
            return requestedBranch.trim();
        }
        List<EphemeralEnvironment> envs = environmentRepository
                .findByRequestedByAndServiceIdWithServiceAndPipelineOrderByCreatedAtDesc(user, applicationId);
        if (!envs.isEmpty() && envs.get(0).getGitBranch() != null && !envs.get(0).getGitBranch().isBlank()) {
            return envs.get(0).getGitBranch().trim();
        }
        return "main";
    }

    private DefectDojoDashboardResponse.DefectDojoDashboardResponseBuilder baseResponse(
            String productName, String branch, String engagementName) {
        return DefectDojoDashboardResponse.builder()
                .productName(productName)
                .engagementName(engagementName)
                .branch(branch)
                .bySeverity(emptySeverityMap())
                .byStatus(Map.of("active", 0, "mitigated", 0, "verified", 0, "falsePositive", 0, "duplicate", 0))
                .metricCards(List.of());
    }

    private static Map<String, Integer> emptySeverityMap() {
        Map<String, Integer> m = new LinkedHashMap<>();
        for (String s : SEVERITIES) m.put(s, 0);
        return m;
    }

    private String productUiUrl(int productId) {
        return properties.normalizedBaseUrl() + "/product/" + productId;
    }

    private String engagementUiUrl(int engagementId) {
        return properties.normalizedBaseUrl() + "/engagement/" + engagementId;
    }

    private String findingUiUrl(int findingId) {
        return properties.normalizedBaseUrl() + "/finding/" + findingId;
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) return v;
        }
        return "";
    }

    private DefectDojoDashboard2Response.DefectDojoDashboard2ResponseBuilder emptyDashboard2(
            AppService app,
            String productName,
            boolean global,
            List<String> branches
    ) {
        Map<String, Integer> emptySev = emptySeverityMap();
        DefectDojoSecurityScore score = computeSecurityScore(emptySev);
        return DefectDojoDashboard2Response.builder()
                .scope(global ? "global" : "branch")
                .applicationName(app.getName())
                .productName(productName)
                .selectedBranch(global ? null : branches.isEmpty() ? "main" : branches.get(0))
                .bySeverity(emptySev)
                .byTool(Map.of())
                .byStatus(Map.of("active", 0, "mitigated", 0, "verified", 0, "falsePositive", 0, "duplicate", 0))
                .totalOpen(0)
                .totalClosed(0)
                .securityScore(score)
                .topRecurrent(List.of())
                .trendPoints(List.of())
                .branches(branches)
                .engagements(List.of())
                .charts(DefectDojoDashboardCharts.builder()
                        .openCount(0)
                        .closedCount(0)
                        .totalCount(0)
                        .bySeverity(emptySev)
                        .byTool(Map.of())
                        .byAnalysisType(Map.of())
                        .byStatus(Map.of())
                        .scanSnapshots(List.of())
                        .build());
    }

    private static boolean isGlobalBranch(String branch) {
        if (branch == null || branch.isBlank()) {
            return true;
        }
        String b = branch.trim().toLowerCase(Locale.ROOT);
        return "__all__".equals(b) || "all".equals(b) || "*".equals(b) || "global".equals(b);
    }

    private DefectDojoFindingsPageResponse listFindingsForProduct(
            UUID applicationId,
            String category,
            String severity,
            int page,
            int size,
            String tags,
            String dateFrom,
            String dateTo,
            Integer testId
    ) {
        User user = currentUser();
        AppService app = applicationRepository.findByIdAndCreatedBy(applicationId, user)
                .orElseThrow(() -> new IllegalArgumentException("Application introuvable ou accès refusé"));
        String productName = extractRepoName(app.getGitRepositoryUrl());
        JsonNode product = findProduct(productName);
        if (product == null) {
            return DefectDojoFindingsPageResponse.builder()
                    .content(List.of())
                    .totalElements(0)
                    .totalPages(0)
                    .page(page)
                    .size(size)
                    .category(category != null ? category : "open")
                    .build();
        }
        int productId = product.path("id").asInt();
        String cat = category != null && !category.isBlank() ? category.trim().toLowerCase() : "open";
        int pageSize = Math.max(1, Math.min(size, 100));
        int offset = Math.max(0, page) * pageSize;

        Map<String, String> params = new LinkedHashMap<>(filtersForCategory(cat));
        params.put("test__engagement__product", String.valueOf(productId));
        if (severity != null && !severity.isBlank()) {
            params.put("severity", normalizeSeverity(severity));
        }
        applyTags(params, tags);
        applyDateAndTestFilters(params, dateFrom, dateTo, testId);
        params.put("ordering", orderingForCategory(cat));
        params.put("limit", String.valueOf(pageSize));
        params.put("offset", String.valueOf(offset));

        JsonNode apiPage = get("/api/v2/findings/", params);
        int total = apiPage != null ? apiPage.path("count").asInt(0) : 0;
        Map<Integer, String> testScanTypes = loadTestScanTypesForProduct(productId);
        List<DefectDojoFindingItem> items = mapFindingPage(apiPage, testScanTypes);
        int totalPages = pageSize > 0 ? (int) Math.ceil(total / (double) pageSize) : 0;

        return DefectDojoFindingsPageResponse.builder()
                .content(items)
                .totalElements(total)
                .totalPages(totalPages)
                .page(page)
                .size(pageSize)
                .category(cat)
                .build();
    }

    private EngagementContext engagementContextFromFinding(
            AppService app,
            String productName,
            int productId,
            JsonNode finding
    ) {
        int engagementId = resolveEngagementIdFromFinding(finding);
        if (engagementId <= 0) {
            return new EngagementContext(app, productName, "main", productName + "_main", productId, 0);
        }
        JsonNode engagement = get("/api/v2/engagements/" + engagementId + "/", null);
        String engagementName = engagement != null ? engagement.path("name").asText(productName + "_main") : productName + "_main";
        String branchTag = engagement != null ? engagement.path("branch_tag").asText(null) : null;
        if (branchTag == null || branchTag.isBlank()) {
            if (engagementName.startsWith(productName + "_")) {
                branchTag = engagementName.substring(productName.length() + 1);
            } else {
                branchTag = "main";
            }
        }
        return new EngagementContext(app, productName, branchTag, engagementName, productId, engagementId);
    }

    private Map<String, Integer> countBySeverityForProduct(int productId) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String sev : SEVERITIES) {
            counts.put(sev, countFindingsForProduct(productId, openFiltersWithSeverity(sev)));
        }
        return counts;
    }

    private Map<String, Integer> countByStatusForProduct(int productId) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        counts.put("active", countFindingsForProduct(productId, OPEN_FILTERS));
        counts.put("mitigated", countFindingsForProduct(productId, Map.of("is_mitigated", "true")));
        counts.put("verified", countFindingsForProduct(productId, Map.of(
                "verified", "true", "active", "true", "is_mitigated", "false")));
        counts.put("falsePositive", countFindingsForProduct(productId, Map.of("false_p", "true")));
        counts.put("duplicate", countFindingsForProduct(productId, Map.of("duplicate", "true")));
        return counts;
    }

    private int countFindingsForProduct(int productId, Map<String, String> extraParams) {
        Map<String, String> params = new LinkedHashMap<>(extraParams);
        params.put("test__engagement__product", String.valueOf(productId));
        params.put("limit", "1");
        JsonNode page = get("/api/v2/findings/", params);
        return page != null ? page.path("count").asInt(0) : 0;
    }

    private List<JsonNode> fetchAllProductFindings(int productId) {
        List<JsonNode> all = new ArrayList<>();
        int offset = 0;
        int pageSize = 100;
        int maxPages = 50;
        for (int i = 0; i < maxPages; i++) {
            JsonNode page = get("/api/v2/findings/", Map.of(
                    "test__engagement__product", String.valueOf(productId),
                    "limit", String.valueOf(pageSize),
                    "offset", String.valueOf(offset),
                    "ordering", "created"
            ));
            if (page == null || !page.has("results")) {
                break;
            }
            JsonNode results = page.path("results");
            if (!results.isArray() || results.isEmpty()) {
                break;
            }
            for (JsonNode f : results) {
                all.add(f);
            }
            int count = page.path("count").asInt(all.size());
            offset += pageSize;
            if (offset >= count) {
                break;
            }
        }
        return all;
    }

    private List<DefectDojoScanSnapshot> buildProductScanSnapshots(
            int productId,
            List<DefectDojoEngagementSummary> engagements
    ) {
        List<DefectDojoScanSnapshot> all = new ArrayList<>();
        for (DefectDojoEngagementSummary e : engagements) {
            if (e.getId() > 0) {
                all.addAll(buildScanSnapshots(e.getId()));
            }
        }
        all.sort(Comparator.comparing(
                DefectDojoScanSnapshot::getTimestamp,
                Comparator.nullsLast(String::compareTo)
        ));
        return all;
    }

    private DefectDojoDashboardCharts buildChartsFromFindings(
            List<JsonNode> findings,
            List<DefectDojoScanSnapshot> scanSnapshots,
            Map<String, Integer> bySeverityOpen,
            Map<String, Integer> byStatus,
            int openCount,
            int closedCount
    ) {
        Map<String, Integer> byTool = new LinkedHashMap<>();
        Map<String, Integer> byAnalysisType = new LinkedHashMap<>();
        for (JsonNode f : findings) {
            if (!isCurrentlyOpen(f)) {
                continue;
            }
            String scanType = resolveScanTypeFromFinding(f);
            byTool.merge(scanType, 1, Integer::sum);
            byAnalysisType.merge(classifyAnalysisType(scanType), 1, Integer::sum);
        }
        DefectDojoDetailedMetrics detailedMetrics = buildDetailedMetrics(findings, findings, scanSnapshots);
        String lastScanDate = scanSnapshots.isEmpty() ? null
                : scanSnapshots.get(scanSnapshots.size() - 1).getDate();

        return DefectDojoDashboardCharts.builder()
                .openCount(openCount)
                .closedCount(closedCount)
                .totalCount(openCount + closedCount)
                .bySeverity(bySeverityOpen)
                .byTool(byTool)
                .byAnalysisType(byAnalysisType)
                .byStatus(byStatus)
                .scanSnapshots(scanSnapshots)
                .detailedMetrics(detailedMetrics)
                .lastScanDate(lastScanDate)
                .build();
    }

    private DefectDojoSecurityScore computeSecurityScore(Map<String, Integer> bySeverity) {
        int critical = bySeverity.getOrDefault("Critical", 0);
        int high = bySeverity.getOrDefault("High", 0);
        int medium = bySeverity.getOrDefault("Medium", 0);

        String grade;
        String summary;
        if (critical == 0 && high == 0) {
            grade = "A";
            summary = "Aucune vulnérabilité critique ou élevée ouverte.";
        } else if (critical == 0 && high <= 3) {
            grade = "B";
            summary = "Quelques vulnérabilités élevées, aucune critique.";
        } else if (critical <= 1 && high <= 10) {
            grade = "C";
            summary = "Risque modéré — prioriser les corrections critiques.";
        } else if (critical <= 3) {
            grade = "D";
            summary = "Risque élevé — plusieurs failles critiques ouvertes.";
        } else {
            grade = "F";
            summary = "Risque critique — action immédiate requise.";
        }
        int score = Math.max(0, Math.min(100, 100 - critical * 15 - high * 5 - medium));
        return DefectDojoSecurityScore.builder().grade(grade).score(score).summary(summary).build();
    }

    private List<DefectDojoRecurrentVulnerability> buildTopRecurrent(List<JsonNode> findings, int limit) {
        Map<String, int[]> acc = new LinkedHashMap<>();
        Map<String, String> types = new LinkedHashMap<>();
        Map<String, String> severities = new LinkedHashMap<>();

        for (JsonNode f : findings) {
            if (!isCurrentlyOpen(f)) {
                continue;
            }
            String cve = extractCve(f);
            String cwe = formatCwe(f);
            String title = f.path("title").asText(null);
            String type;
            String identifier;
            if (cve != null && !cve.isBlank()) {
                type = "CVE";
                identifier = cve;
            } else if (cwe != null) {
                type = "CWE";
                identifier = cwe;
            } else {
                type = "Finding";
                identifier = title != null && !title.isBlank() ? title : "Sans titre";
            }
            acc.merge(identifier, new int[]{1}, (a, b) -> new int[]{a[0] + b[0]});
            types.putIfAbsent(identifier, type);
            severities.putIfAbsent(identifier, normalizeSeverity(f.path("severity").asText("Info")));
        }

        return acc.entrySet().stream()
                .sorted((a, b) -> Integer.compare(b.getValue()[0], a.getValue()[0]))
                .limit(limit)
                .map(e -> DefectDojoRecurrentVulnerability.builder()
                        .identifier(e.getKey())
                        .label(e.getKey())
                        .count(e.getValue()[0])
                        .type(types.get(e.getKey()))
                        .severity(severities.get(e.getKey()))
                        .build())
                .toList();
    }

    private List<DefectDojoTrendPoint> buildTrendPoints(DefectDojoDashboardCharts charts) {
        if (charts == null || charts.getScanSnapshots() == null) {
            return List.of();
        }
        return buildTrendPoints(charts.getScanSnapshots());
    }

    private List<DefectDojoTrendPoint> buildTrendPoints(List<DefectDojoScanSnapshot> snapshots) {
        if (snapshots == null || snapshots.isEmpty()) {
            return List.of();
        }
        List<DefectDojoScanSnapshot> sorted = new ArrayList<>(snapshots);
        sorted.sort(Comparator.comparing(
                DefectDojoScanSnapshot::getTimestamp,
                Comparator.nullsLast(String::compareTo)
        ));

        List<DefectDojoTrendPoint> points = new ArrayList<>();
        int prevOpen = 0;
        for (DefectDojoScanSnapshot snap : sorted) {
            int open = snap.getTotalOpen();
            int newF = points.isEmpty() ? open : Math.max(0, open - prevOpen);
            int resolved = points.isEmpty() ? 0 : Math.max(0, prevOpen - open);
            points.add(DefectDojoTrendPoint.builder()
                    .label(snap.getLabel() != null ? snap.getLabel() : snap.getDate())
                    .date(snap.getDate())
                    .openStock(open)
                    .newFindings(newF)
                    .resolved(resolved)
                    .build());
            prevOpen = open;
        }
        return points;
    }

    private List<DefectDojoEngagementSummary> listEngagementsForProductLight(int productId, String productName) {
        JsonNode page = get("/api/v2/engagements/", Map.of(
                "product", String.valueOf(productId),
                "limit", "100",
                "ordering", "-id"
        ));
        if (page == null) {
            return List.of();
        }
        List<DefectDojoEngagementSummary> out = new ArrayList<>();
        for (JsonNode item : page.path("results")) {
            int id = item.path("id").asInt();
            String name = item.path("name").asText();
            String branchTag = item.path("branch_tag").asText(null);
            if ((branchTag == null || branchTag.isBlank()) && name.startsWith(productName + "_")) {
                branchTag = name.substring(productName.length() + 1);
            }
            out.add(DefectDojoEngagementSummary.builder()
                    .id(id)
                    .name(name)
                    .branchTag(branchTag)
                    .status(item.path("status").asText(null))
                    .activeFindings(0)
                    .url(engagementUiUrl(id))
                    .build());
        }
        return out;
    }

    private List<JsonNode> fetchOpenFindingsSample(Integer productId, Integer engagementId, int limit) {
        return fetchOpenFindingsSample(productId, engagementId, limit, null);
    }

    private List<JsonNode> fetchOpenFindingsSample(Integer productId, Integer engagementId, int limit, String tags) {
        Map<String, String> params = new LinkedHashMap<>(filtersForCategory("open"));
        if (engagementId != null) {
            params.put("test__engagement", String.valueOf(engagementId));
        } else if (productId != null) {
            params.put("test__engagement__product", String.valueOf(productId));
        }
        applyTags(params, tags);
        params.put("limit", String.valueOf(Math.min(limit, 200)));
        params.put("ordering", "-numerical_severity,-id");
        JsonNode page = get("/api/v2/findings/", params);
        if (page == null || !page.has("results")) {
            return List.of();
        }
        List<JsonNode> out = new ArrayList<>();
        for (JsonNode f : page.path("results")) {
            out.add(f);
        }
        return out;
    }

    /** Tests DefectDojo tagués env-{uuid} (aligné import CI). */
    private JsonNode fetchTestsWithTag(int engagementId, String tag) {
        if (tag == null || tag.isBlank()) {
            return null;
        }
        return get("/api/v2/tests/", Map.of(
                "engagement", String.valueOf(engagementId),
                "tags", tag.trim(),
                "limit", "100",
                "ordering", "-id"
        ));
    }

    private Map<String, Integer> aggregateToolsFromEngagementWithTag(int engagementId, String tag) {
        JsonNode page = fetchTestsWithTag(engagementId, tag);
        return aggregateToolsFromTestsPage(page, false);
    }

    private Map<String, Integer> parallelCountBySeverityForTaggedTests(int engagementId, String tag) {
        JsonNode page = fetchTestsWithTag(engagementId, tag);
        Map<String, Integer> total = emptySeverityMap();
        if (page == null || !page.has("results")) {
            return total;
        }
        for (JsonNode t : page.path("results")) {
            int testId = t.path("id").asInt();
            if (testId <= 0) continue;
            countBySeverityForTest(testId, true).forEach((sev, count) ->
                    total.merge(sev, count, Integer::sum));
        }
        return total;
    }

    private List<JsonNode> fetchOpenFindingsSampleForTaggedTests(
            Integer productId,
            int engagementId,
            String tag,
            int limit
    ) {
        JsonNode page = fetchTestsWithTag(engagementId, tag);
        if (page == null || !page.has("results")) {
            return List.of();
        }
        List<JsonNode> out = new ArrayList<>();
        for (JsonNode t : page.path("results")) {
            int testId = t.path("id").asInt();
            if (testId <= 0) continue;
            Map<String, String> params = new LinkedHashMap<>(filtersForCategory("open"));
            params.put("test", String.valueOf(testId));
            params.put("limit", String.valueOf(Math.min(limit, 200)));
            params.put("ordering", "-numerical_severity,-id");
            JsonNode findingsPage = get("/api/v2/findings/", params);
            if (findingsPage != null && findingsPage.has("results")) {
                for (JsonNode f : findingsPage.path("results")) {
                    out.add(f);
                    if (out.size() >= limit) {
                        return out;
                    }
                }
            }
        }
        return out;
    }

    private Map<String, Integer> aggregateToolsFromFindings(List<JsonNode> findings) {
        Map<String, Integer> byTool = new LinkedHashMap<>();
        for (JsonNode f : findings) {
            byTool.merge(resolveScanTypeFromFinding(f), 1, Integer::sum);
        }
        return byTool;
    }

    /** Noms de scan DefectDojo (scan_type) — aligné pipeline CI. */
    private Map<String, Integer> aggregateToolsFromEngagement(int engagementId) {
        JsonNode page = get("/api/v2/tests/", Map.of(
                "engagement", String.valueOf(engagementId),
                "limit", "100",
                "ordering", "-id"
        ));
        return aggregateToolsFromTestsPage(page, false);
    }

    /** Vue globale : tous les tests du produit (toutes branches). */
    private Map<String, Integer> aggregateToolsFromProductTests(int productId) {
        JsonNode page = get("/api/v2/tests/", Map.of(
                "test__engagement__product", String.valueOf(productId),
                "limit", "100",
                "ordering", "-id"
        ));
        return aggregateToolsFromTestsPage(page, true);
    }

    private Map<String, Integer> aggregateToolsFromTestsPage(JsonNode page, boolean includeZeroCounts) {
        Map<String, Integer> byTool = new LinkedHashMap<>();
        if (page == null || !page.has("results")) {
            return byTool;
        }
        for (JsonNode t : page.path("results")) {
            String scanType = resolveScanTypeFromTest(t);
            if (scanType == null) {
                continue;
            }
            int count = t.path("finding_count").asInt(0);
            if (count == 0 && !includeZeroCounts) {
                int testId = t.path("id").asInt();
                count = countFindingsForTest(testId, Map.of(
                        "active", "true",
                        "is_mitigated", "false",
                        "duplicate", "false"
                ));
            }
            if (count > 0) {
                byTool.merge(scanType, count, Integer::sum);
            } else if (includeZeroCounts) {
                byTool.putIfAbsent(scanType, 0);
            }
        }
        return byTool;
    }

    private Map<String, Integer> aggregateToolsFromEngagements(List<DefectDojoEngagementSummary> engagements) {
        Map<String, Integer> byTool = new LinkedHashMap<>();
        int max = Math.min(engagements.size(), 12);
        for (int i = 0; i < max; i++) {
            DefectDojoEngagementSummary e = engagements.get(i);
            if (e.getId() > 0) {
                aggregateToolsFromEngagement(e.getId()).forEach((k, v) -> byTool.merge(k, v, Integer::sum));
            }
        }
        return byTool;
    }

    /** Vue globale : noms de scanners uniquement (pas de cumul de findings). */
    private Map<String, Integer> aggregateToolsPresenceFromEngagements(List<DefectDojoEngagementSummary> engagements) {
        return aggregateToolsPresenceFromEngagements(engagements, 3);
    }

    private Map<String, Integer> aggregateToolsPresenceFromEngagements(
            List<DefectDojoEngagementSummary> engagements,
            int maxEngagements
    ) {
        LinkedHashSet<String> names = new LinkedHashSet<>();
        int max = Math.min(engagements.size(), Math.max(1, maxEngagements));
        for (int i = 0; i < max; i++) {
            DefectDojoEngagementSummary e = engagements.get(i);
            if (e.getId() > 0) {
                aggregateToolsFromEngagement(e.getId()).keySet().forEach(names::add);
            }
        }
        Map<String, Integer> byTool = new LinkedHashMap<>();
        for (String name : names) {
            byTool.put(name, 0);
        }
        return byTool;
    }

    private Map<String, Integer> aggregateToolsPresenceFromFindings(List<JsonNode> findings) {
        LinkedHashSet<String> names = new LinkedHashSet<>();
        for (JsonNode f : findings) {
            names.add(resolveScanTypeFromFinding(f));
        }
        Map<String, Integer> byTool = new LinkedHashMap<>();
        for (String name : names) {
            byTool.put(name, 0);
        }
        return byTool;
    }

    /** Graphique Open by Severity — branche (engagement) ou vue globale produit. */
    private DefectDojoDashboardCharts buildDashboard2Charts(int engagementId, Map<String, Integer> bySeverity) {
        List<DefectDojoScanSnapshot> scanSnapshots = buildScanSnapshotsFast(engagementId);
        List<JsonNode> findings = fetchAllEngagementFindings(engagementId);
        List<DefectDojoTimeSeriesPoint> openDayToDay = buildOpenDayToDayFromFindings(findings);
        DefectDojoDetailedMetrics detailedMetrics = DefectDojoDetailedMetrics.builder()
                .openDayToDayBySeverity(openDayToDay)
                .build();
        return DefectDojoDashboardCharts.builder()
                .scanSnapshots(scanSnapshots)
                .bySeverity(bySeverity)
                .detailedMetrics(detailedMetrics)
                .build();
    }

    private DefectDojoDashboardCharts buildDashboard2ChartsForGlobal(
            int productId,
            Map<String, Integer> bySeverity,
            List<DefectDojoEngagementSummary> engagements
    ) {
        List<JsonNode> findings = fetchAllProductFindings(productId);
        List<DefectDojoTimeSeriesPoint> openDayToDay = buildOpenDayToDayFromFindings(findings);
        List<DefectDojoScanSnapshot> scanSnapshots = (engagements != null && !engagements.isEmpty())
                ? buildProductScanSnapshotsFast(engagements)
                : buildProductScanSnapshotsForChart(productId, 50);
        DefectDojoDetailedMetrics detailedMetrics = DefectDojoDetailedMetrics.builder()
                .openDayToDayBySeverity(openDayToDay)
                .build();
        return DefectDojoDashboardCharts.builder()
                .scanSnapshots(scanSnapshots)
                .bySeverity(bySeverity)
                .detailedMetrics(detailedMetrics)
                .build();
    }

    /** Tests DefectDojo agrégés au niveau produit (toutes branches / engagements). */
    private List<DefectDojoScanSnapshot> buildProductScanSnapshotsForChart(int productId, int limit) {
        JsonNode page = get("/api/v2/tests/", Map.of(
                "test__engagement__product", String.valueOf(productId),
                "limit", String.valueOf(Math.min(Math.max(limit, 1), 50)),
                "ordering", "created"
        ));
        return buildScanSnapshotsFromTestsPage(page, false);
    }

    private static final int MAX_DAY_TO_DAY_POINTS = 365;

    /**
     * Série « Open Day to Day by Severity » — stock cumulé jour par jour (créations / clôtures),
     * avec un point pour chaque jour calendaire jusqu'à aujourd'hui.
     */
    private List<DefectDojoTimeSeriesPoint> buildOpenDayToDayFromFindings(List<JsonNode> findings) {
        if (findings == null || findings.isEmpty()) {
            return List.of();
        }
        TreeMap<String, Map<String, Integer>> dailyDelta = new TreeMap<>();
        for (JsonNode f : findings) {
            if (f.path("duplicate").asBoolean(false) || f.path("false_p").asBoolean(false)) {
                continue;
            }
            String sev = normalizeSeverity(f.path("severity").asText("Info"));
            String createdDay = extractDay(f.path("created").asText(null));
            if (createdDay != null) {
                dailyDelta.computeIfAbsent(createdDay, k -> new LinkedHashMap<>(emptySeverityMap()))
                        .merge(sev, 1, Integer::sum);
            }
            if (f.path("is_mitigated").asBoolean(false) || !f.path("active").asBoolean(true)) {
                String mitDay = extractDay(firstNonBlank(
                        f.path("mitigated").asText(null),
                        f.path("last_status_update").asText(null),
                        f.path("last_reviewed").asText(null)
                ));
                if (mitDay != null) {
                    dailyDelta.computeIfAbsent(mitDay, k -> new LinkedHashMap<>(emptySeverityMap()))
                            .merge(sev, -1, Integer::sum);
                }
            }
        }
        if (dailyDelta.isEmpty()) {
            return List.of();
        }

        String start = dailyDelta.firstKey();
        String end = java.time.LocalDate.now().toString();
        String lastEvent = dailyDelta.lastKey();
        if (lastEvent.compareTo(end) > 0) {
            end = lastEvent;
        }

        List<String> timeline = expandDayRange(start, end);
        Map<String, Integer> cumulative = new LinkedHashMap<>(emptySeverityMap());
        List<DefectDojoTimeSeriesPoint> points = new ArrayList<>();
        for (String day : timeline) {
            Map<String, Integer> delta = dailyDelta.get(day);
            if (delta != null) {
                for (Map.Entry<String, Integer> e : delta.entrySet()) {
                    cumulative.merge(e.getKey(), e.getValue(), Integer::sum);
                    cumulative.put(e.getKey(), Math.max(0, cumulative.getOrDefault(e.getKey(), 0)));
                }
            }
            points.add(DefectDojoTimeSeriesPoint.builder()
                    .period(day)
                    .bySeverity(new LinkedHashMap<>(cumulative))
                    .build());
        }
        return points;
    }

    /** @deprecated remplacé par {@link #buildOpenDayToDayFromFindings} */
    private List<DefectDojoTimeSeriesPoint> buildOpenDayToDayCumulative(List<JsonNode> openFindings) {
        return buildOpenDayToDayFromFindings(openFindings);
    }

    private static List<String> expandDayRange(String startDay, String endDay) {
        if (startDay == null || endDay == null) {
            return List.of();
        }
        try {
            java.time.LocalDate start = java.time.LocalDate.parse(startDay);
            java.time.LocalDate end = java.time.LocalDate.parse(endDay);
            if (end.isBefore(start)) {
                java.time.LocalDate tmp = start;
                start = end;
                end = tmp;
            }
            long span = java.time.temporal.ChronoUnit.DAYS.between(start, end) + 1;
            if (span > MAX_DAY_TO_DAY_POINTS) {
                start = end.minusDays(MAX_DAY_TO_DAY_POINTS - 1L);
            }
            List<String> days = new ArrayList<>();
            for (java.time.LocalDate d = start; !d.isAfter(end); d = d.plusDays(1)) {
                days.add(d.toString());
            }
            return days;
        } catch (Exception e) {
            return List.of(startDay, endDay);
        }
    }

    private List<DefectDojoScanSnapshot> buildProductScanSnapshotsFast(List<DefectDojoEngagementSummary> engagements) {
        List<DefectDojoScanSnapshot> all = new ArrayList<>();
        for (DefectDojoEngagementSummary e : engagements) {
            if (e.getId() > 0) {
                all.addAll(buildScanSnapshotsFast(e.getId()));
            }
        }
        all.sort(Comparator.comparing(
                DefectDojoScanSnapshot::getTimestamp,
                Comparator.nullsLast(String::compareTo)
        ));
        return all;
    }

    private List<DefectDojoScanSnapshot> buildScanSnapshotsFast(int engagementId) {
        JsonNode page = get("/api/v2/tests/", Map.of(
                "engagement", String.valueOf(engagementId),
                "limit", "10",
                "ordering", "-created"
        ));
        return buildScanSnapshotsFromTestsPage(page, false);
    }

    private List<DefectDojoScanSnapshot> buildScanSnapshotsFromTestsPage(JsonNode page, boolean resolveFindingDates) {
        if (page == null) {
            return List.of();
        }

        List<JsonNode> tests = new ArrayList<>();
        for (JsonNode t : page.path("results")) {
            tests.add(t);
        }

        Map<Integer, Map<String, Integer>> severityByTest = new ConcurrentHashMap<>();
        Map<Integer, Integer> totalByTest = new ConcurrentHashMap<>();

        List<CompletableFuture<Void>> futures = new ArrayList<>();
        for (JsonNode t : tests) {
            int testId = t.path("id").asInt();
            futures.add(CompletableFuture.runAsync(() -> {
                Map<String, Integer> bySev = countBySeverityForTest(testId, true);
                severityByTest.put(testId, bySev);
                totalByTest.put(testId, bySev.values().stream().mapToInt(Integer::intValue).sum());
            }, DD_IO_POOL));
        }
        joinAll(futures);

        List<DefectDojoScanSnapshot> out = new ArrayList<>();
        for (JsonNode t : tests) {
            int testId = t.path("id").asInt();
            Map<String, Integer> bySev = severityByTest.getOrDefault(testId, emptySeverityMap());
            int total = totalByTest.getOrDefault(testId, 0);
            String scanType = resolveScanTypeFromTest(t);
            if (scanType == null) {
                scanType = "Unknown";
            }
            String timestamp = resolveFindingDates
                    ? resolveTestTimestamp(t, testId)
                    : resolveTestTimestampLight(t);
            String date = extractDay(timestamp);
            String label = formatScanLabel(scanType, timestamp);
            out.add(DefectDojoScanSnapshot.builder()
                    .testId(testId)
                    .scanType(scanType)
                    .label(label)
                    .date(date)
                    .timestamp(timestamp)
                    .totalOpen(total)
                    .bySeverity(bySev)
                    .build());
        }
        return out;
    }

    // Ancienne surcharge conservée pour compatibilité interne
    private List<DefectDojoScanSnapshot> buildScanSnapshotsFast(int engagementId, int limit, boolean resolveFindingDates) {
        JsonNode page = get("/api/v2/tests/", Map.of(
                "engagement", String.valueOf(engagementId),
                "limit", String.valueOf(limit),
                "ordering", "created"
        ));
        return buildScanSnapshotsFromTestsPage(page, resolveFindingDates);
    }

    private String resolveTestTimestamp(JsonNode test, int testId) {
        return firstNonBlank(
                resolveTestTimestampLight(test),
                fetchEarliestFindingCreated(testId)
        );
    }

    /** Sans appel API findings/test — utilisé par dashboard2 pour éviter des centaines de requêtes. */
    private static String resolveTestTimestampLight(JsonNode test) {
        return firstNonBlank(
                test.path("target_end").asText(null),
                test.path("target_start").asText(null),
                test.path("updated").asText(null),
                test.path("created").asText(null)
        );
    }

    private String fetchEarliestFindingCreated(int testId) {
        JsonNode page = get("/api/v2/findings/", Map.of(
                "test", String.valueOf(testId),
                "ordering", "created",
                "limit", "1"
        ));
        if (page == null) {
            return null;
        }
        JsonNode results = page.path("results");
        if (!results.isArray() || results.isEmpty()) {
            return null;
        }
        return results.get(0).path("created").asText(null);
    }

    private static String formatScanLabel(String scanType, String timestamp) {
        if (timestamp == null || timestamp.isBlank()) {
            return scanType;
        }
        String day = extractDay(timestamp);
        if (day == null) {
            return scanType;
        }
        if (timestamp.length() >= 16 && timestamp.charAt(10) == 'T') {
            return scanType + " · " + day + " " + timestamp.substring(11, 16);
        }
        return scanType + " · " + day;
    }

    private User currentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getName() == null || auth.getName().isBlank()) {
            throw new IllegalStateException("Utilisateur non authentifié");
        }
        return userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new IllegalStateException("Utilisateur non trouvé"));
    }
}
