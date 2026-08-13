package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatch;
import com.backend.devsecopsplatform_backend.service.qualitygate.HardGateInput;
import com.backend.devsecopsplatform_backend.service.qualitygate.SecurityScoreInput;
import com.backend.devsecopsplatform_backend.service.qualitygate.SecurityScoringService;
import com.backend.devsecopsplatform_backend.service.qualitygate.dto.SecurityScoreDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Agrégation D5 du verdict application à partir des {@code qualityGateJson} figés (D6).
 * <p>
 * Invariants :
 * <ul>
 *   <li>hard gate violé sur un service → {@code NOT_RECOMMENDED}, score null</li>
 *   <li>indéterminé sur un service → pas {@code RECOMMENDED} ({@code INDETERMINE})</li>
 *   <li>score = min des scores ajustés (pas de moyenne) ; worker +10 avant min → FRONTEND pèse plus</li>
 * </ul>
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class ScanBatchAggregationService {

    /** Biais worker : score interne relevé avant le min → un FRONTEND faible domine davantage. */
    static final int WORKER_SCORE_RELAXATION = 10;

    private static final List<String> VERDICT_SEVERITY = List.of(
            "NOT_RECOMMENDED", "INDETERMINE", "WITH_WARNINGS", "RECOMMENDED");

    private final SecurityScoringService securityScoringService;

    public record ServiceContribution(
            String pipelineExecutionId,
            String serviceId,
            String serviceName,
            String serviceRole,
            boolean publiclyExposed,
            String verdict,
            Integer securityScore,
            String grade,
            boolean hardGateViolated,
            boolean indeterminate,
            List<String> hardGateIds,
            List<String> indeterminateSources
    ) {}

    public record AggregationResult(
            String verdict,
            Integer securityScore,
            String grade,
            List<ServiceContribution> services,
            Map<String, Object> payloadExtras
    ) {}

    /**
     * Agrège les exécutions d'un lot COMPLETE. Les PE doivent idéalement avoir
     * {@code appService} chargé (JOIN FETCH) pour le rôle / exposition.
     */
    public AggregationResult aggregate(ScanBatch batch, List<PipelineExecution> executions) {
        List<ServiceContribution> contribs = new ArrayList<>();
        for (PipelineExecution pe : executions) {
            contribs.add(evaluateService(pe));
        }

        boolean anyHardGate = contribs.stream().anyMatch(ServiceContribution::hardGateViolated);
        boolean anyIndeterminate = contribs.stream().anyMatch(ServiceContribution::indeterminate);

        String verdict;
        Integer score = null;
        String grade = null;
        ServiceContribution dimensioning = null;

        if (anyHardGate) {
            verdict = "NOT_RECOMMENDED";
        } else if (anyIndeterminate) {
            verdict = "INDETERMINE";
        } else {
            verdict = worstVerdict(contribs.stream().map(ServiceContribution::verdict).toList());
            // Relaxation worker uniquement pour sélectionner le service dimensionnant ;
            // le score reporté reste le score réel (cohérent hub service ↔ app).
            if ("RECOMMENDED".equals(verdict) || "WITH_WARNINGS".equals(verdict)) {
                dimensioning = contribs.stream()
                        .filter(c -> c.securityScore() != null)
                        .min(Comparator.comparingInt(ScanBatchAggregationService::adjustedScoreForSelection))
                        .orElse(null);
                if (dimensioning != null) {
                    score = dimensioning.securityScore();
                    grade = SecurityScoringService.scoreToGrade(score);
                    if (score < 75 && "RECOMMENDED".equals(verdict)) {
                        verdict = "WITH_WARNINGS";
                    }
                }
            }
        }

        Map<String, Object> extras = new LinkedHashMap<>();
        extras.put("aggregation", "D5_WORST_CASE_MIN_ADJUSTED");
        extras.put("workerScoreRelaxation", WORKER_SCORE_RELAXATION);
        extras.put("expectedServiceCount", batch != null ? batch.getExpectedServiceCount() : executions.size());
        extras.put("aggregatedServiceCount", contribs.size());
        if (anyHardGate) {
            extras.put("blockingReason", "HARD_GATE_ON_AT_LEAST_ONE_SERVICE");
        } else if (anyIndeterminate) {
            extras.put("blockingReason", "INDETERMINATE_ON_AT_LEAST_ONE_SERVICE");
        }
        if (dimensioning != null) {
            Map<String, Object> dimensioningService = new LinkedHashMap<>();
            dimensioningService.put("serviceId", dimensioning.serviceId());
            dimensioningService.put("serviceName", dimensioning.serviceName());
            dimensioningService.put("serviceRole", dimensioning.serviceRole());
            dimensioningService.put("publiclyExposed", dimensioning.publiclyExposed());
            dimensioningService.put("securityScore", dimensioning.securityScore());
            dimensioningService.put("grade", dimensioning.grade());
            dimensioningService.put("adjustedScoreForSelection", adjustedScoreForSelection(dimensioning));
            extras.put("dimensioningService", dimensioningService);
        }

        return new AggregationResult(verdict, score, grade, contribs, extras);
    }

    /** Score utilisé uniquement pour choisir le service dimensionnant (pas stocké). */
    static int adjustedScoreForSelection(ServiceContribution c) {
        int s = c.securityScore() != null ? c.securityScore() : Integer.MAX_VALUE;
        if (!c.publiclyExposed()) {
            s = Math.min(100, s + WORKER_SCORE_RELAXATION);
        }
        return s;
    }

    ServiceContribution evaluateService(PipelineExecution pe) {
        AppService svc = pe.getAppService();
        Map<String, Object> gate = pe.getQualityGateJson() != null ? pe.getQualityGateJson() : Map.of();

        boolean publiclyExposed = isPubliclyExposed(svc);
        String roleName = svc != null && svc.getRole() != null ? svc.getRole().name() : null;

        HardGateInput hardIn = buildHardGateInput(gate);
        SecurityScoringService.HardGateEvaluation hard = securityScoringService.evaluateHardGates(hardIn);

        boolean violated = !hard.violations().isEmpty();
        boolean indeterminate = !hard.indeterminate().isEmpty()
                || !hard.indeterminateSources().isEmpty();

        Integer score = null;
        String grade = null;
        String verdict;
        if (violated || indeterminate) {
            verdict = securityScoringService.resolveDeterministicVerdict(hard, null);
        } else {
            SecurityScoreDto posture = securityScoringService.computePostureScore(buildScoreInput(gate));
            score = posture.getScore();
            grade = posture.getGrade();
            verdict = securityScoringService.resolveDeterministicVerdict(hard, posture);
        }

        List<String> gateIds = hard.violations().stream().map(v -> v.getId()).toList();
        List<String> indeterminateLabels = new ArrayList<>(hard.indeterminateSources());
        hard.indeterminate().forEach(v -> {
            if (v.getId() != null && !indeterminateLabels.contains(v.getId())) {
                indeterminateLabels.add(v.getId());
            }
        });
        return new ServiceContribution(
                pe.getId() != null ? pe.getId().toString() : null,
                svc != null && svc.getId() != null ? svc.getId().toString() : null,
                svc != null ? svc.getName() : null,
                roleName,
                publiclyExposed,
                verdict,
                score,
                grade,
                violated,
                indeterminate,
                gateIds,
                indeterminateLabels
        );
    }

    static boolean isPubliclyExposed(AppService svc) {
        if (svc == null) {
            return false;
        }
        if (svc.getRole() == AppServiceRole.FRONTEND) {
            return true;
        }
        return svc.getExposedPort() != null && svc.getExposedPort() > 0;
    }

    /**
     * Construit HardGateInput depuis le qualityGateJson figé (D6).
     * Préfère {@code ddBySeverity} (DefectDojo figé au snapshot) aux compteurs CI Trivy.
     */
    static HardGateInput buildHardGateInput(Map<String, Object> gate) {
        boolean secretsPresent = gate.containsKey("secrets");
        int secrets = intVal(gate, "secrets");
        Map<String, Integer> ddSev = resolveDdBySeverity(gate);
        int critical = ddSev.getOrDefault("critical", intVal(gate, "critical"));
        int sonarCritical = firstPresent(gate, "sonarCriticals", "sonar_criticals");
        int sonarBlockers = firstPresent(gate, "sonarBlockers", "sonar_blockers");
        String qg = firstString(gate, "sonarQualityGate", "sonar_quality_gate");

        boolean sonarAvailable = isSonarFrozenAvailable(gate, qg, sonarBlockers, sonarCritical);
        boolean ddAvailable = gate.containsKey("ddBySeverity")
                || gate.containsKey("critical") || gate.containsKey("high")
                || (gate.get("summary") instanceof Map<?, ?>);

        return HardGateInput.builder()
                .secrets(secrets)
                .secretsEvaluable(secretsPresent)
                .ddCritical(critical)
                .sonarCritical(Math.max(0, sonarCritical))
                .sonarBlockers(Math.max(0, sonarBlockers))
                .sonarQgStatus(qg)
                .defectDojoAvailable(ddAvailable)
                .sonarAvailable(sonarAvailable)
                .build();
    }

    static SecurityScoreInput buildScoreInput(Map<String, Object> gate) {
        Map<String, Integer> dd = resolveDdBySeverity(gate);
        if (dd.values().stream().allMatch(v -> v == null || v == 0)
                && !gate.containsKey("ddBySeverity")) {
            dd.put("critical", intVal(gate, "critical"));
            dd.put("high", intVal(gate, "high"));
            dd.put("medium", intVal(gate, "scaMedium"));
            dd.put("low", 0);
            if (gate.get("summary") instanceof Map<?, ?> summary) {
                Object sca = summary.get("sca");
                if (sca instanceof Map<?, ?> scaMap) {
                    dd.put("critical", intObj(scaMap.get("critical"), dd.get("critical")));
                    dd.put("high", intObj(scaMap.get("high"), dd.get("high")));
                    dd.put("medium", intObj(scaMap.get("medium"), dd.get("medium")));
                    dd.put("low", intObj(scaMap.get("low"), 0));
                }
            }
        }

        String qg = firstString(gate, "sonarQualityGate", "sonar_quality_gate");
        int ncloc = firstPresent(gate, "sonarNcloc", "sonar_ncloc");
        int hotspots = firstPresent(gate, "sonarHotspots", "sonar_hotspots");
        String rating = firstString(gate, "sonarSecurityRating", "sonar_security_rating");

        return SecurityScoreInput.builder()
                .ddBySeverity(dd)
                .secrets(intVal(gate, "secrets"))
                .containerCritical(intVal(gate, "containerCritical"))
                .sonarQgStatus(qg)
                .securityRating(rating)
                .securityHotspots(Math.max(0, hotspots))
                .ncloc(Math.max(0, ncloc))
                .stages(List.of())
                .sonarAvailable(isSonarFrozenAvailable(gate, qg,
                        firstPresent(gate, "sonarBlockers", "sonar_blockers"),
                        firstPresent(gate, "sonarCriticals", "sonar_criticals")))
                .defectDojoAvailable(true)
                .sonarBlockers(Math.max(0, firstPresent(gate, "sonarBlockers", "sonar_blockers")))
                .coverageKnown(false)
                .build();
    }

    /**
     * Compteurs DD figés ({@code ddBySeverity}) ou fallback {@code displaySnapshot.metrics.bySeverity}.
     */
    @SuppressWarnings("unchecked")
    static Map<String, Integer> resolveDdBySeverity(Map<String, Object> gate) {
        Map<String, Integer> out = emptySeverityMap();
        if (gate == null) {
            return out;
        }
        Object raw = gate.get("ddBySeverity");
        if (!(raw instanceof Map<?, ?>) && gate.get("displaySnapshot") instanceof Map<?, ?> snap) {
            Object metrics = snap.get("metrics");
            if (metrics instanceof Map<?, ?> m) {
                raw = m.get("bySeverity");
            }
        }
        if (raw instanceof Map<?, ?> m) {
            for (String k : List.of("critical", "high", "medium", "low", "info")) {
                Object v = m.get(k);
                if (v == null) {
                    v = m.get(Character.toUpperCase(k.charAt(0)) + k.substring(1));
                }
                out.put(k, intObj(v, 0));
            }
        }
        return out;
    }

    static Map<String, Integer> emptySeverityMap() {
        Map<String, Integer> out = new LinkedHashMap<>();
        out.put("critical", 0);
        out.put("high", 0);
        out.put("medium", 0);
        out.put("low", 0);
        out.put("info", 0);
        return out;
    }

    /**
     * Rollup app : somme des sévérités DD + top findings bloquants (avec serviceId).
     */
    @SuppressWarnings("unchecked")
    static void attachDefectDojoAppRollup(List<PipelineExecution> executions, Map<String, Object> payload) {
        Map<String, Integer> aggregated = emptySeverityMap();
        List<Map<String, Object>> top = new ArrayList<>();

        for (PipelineExecution pe : executions) {
            Map<String, Object> gate = pe.getQualityGateJson() != null ? pe.getQualityGateJson() : Map.of();
            Map<String, Integer> sev = resolveDdBySeverity(gate);
            for (String k : aggregated.keySet()) {
                aggregated.put(k, aggregated.get(k) + sev.getOrDefault(k, 0));
            }
            AppService svc = pe.getAppService();
            String serviceId = svc != null && svc.getId() != null ? svc.getId().toString() : null;
            String serviceName = svc != null ? svc.getName() : null;
            Object rawTop = gate.get("ddTopBlockingFindings");
            if (rawTop instanceof List<?> list) {
                for (Object o : list) {
                    if (!(o instanceof Map<?, ?> src)) {
                        continue;
                    }
                    Map<String, Object> row = new LinkedHashMap<>();
                    src.forEach((k, v) -> row.put(String.valueOf(k), v));
                    row.put("serviceId", serviceId);
                    row.put("serviceName", serviceName);
                    top.add(row);
                }
            }
        }

        top.sort(Comparator
                .comparingInt((Map<String, Object> r) -> blockingSeverityRank(String.valueOf(r.get("severity"))))
                .thenComparing(r -> String.valueOf(r.getOrDefault("title", ""))));
        if (top.size() > 15) {
            top = new ArrayList<>(top.subList(0, 15));
        }

        payload.put("aggregatedBySeverity", aggregated);
        payload.put("topBlockingFindings", top);
        payload.put("defectDojoRollupSource", "FROZEN_QUALITY_GATE_DD");
    }

    private static int blockingSeverityRank(String severity) {
        if (severity == null) {
            return 99;
        }
        String s = severity.trim().toLowerCase();
        if (s.startsWith("crit")) {
            return 0;
        }
        if (s.startsWith("high")) {
            return 1;
        }
        if (s.startsWith("med")) {
            return 2;
        }
        return 50;
    }

    static boolean isSonarFrozenAvailable(
            Map<String, Object> gate, String qg, int blockers, int criticals
    ) {
        if (gate.containsKey("sonar_available")) {
            Object v = gate.get("sonar_available");
            if (v instanceof Boolean b) {
                return b;
            }
        }
        if (qg != null && !qg.isBlank() && !"N/A".equalsIgnoreCase(qg) && !"null".equalsIgnoreCase(qg)) {
            return true;
        }
        return blockers > 0 || criticals > 0 || gate.containsKey("sonarBugs") || gate.containsKey("sonarNcloc");
    }

    /** Variante simple depuis qualityGateJson figé. */
    static boolean isSonarAvailableFromGate(Map<String, Object> gate) {
        if (gate == null || gate.isEmpty()) {
            return false;
        }
        String qg = firstString(gate, "sonarQualityGate", "sonar_quality_gate");
        int blockers = firstPresent(gate, "sonarBlockers", "sonar_blockers");
        int criticals = firstPresent(gate, "sonarCriticals", "sonar_criticals");
        return isSonarFrozenAvailable(gate, qg, blockers, criticals);
    }

    static String worstVerdict(List<String> verdicts) {
        return verdicts.stream()
                .filter(v -> v != null && !v.isBlank())
                .min(Comparator.comparingInt(ScanBatchAggregationService::severityIndex))
                .orElse("INDETERMINE");
    }

    private static int severityIndex(String verdict) {
        String n = normalize(verdict);
        int i = VERDICT_SEVERITY.indexOf(n);
        return i >= 0 ? i : 1; // unknown → near INDETERMINE
    }

    static String normalize(String raw) {
        if (raw == null) {
            return "INDETERMINE";
        }
        String u = raw.trim().toUpperCase();
        if (u.contains("NON_RECOMMANDE") || u.contains("NOT_RECOMMENDED")) {
            return "NOT_RECOMMENDED";
        }
        if (u.contains("WARN") || u.contains("DEPLOY_WITH_WARNINGS") || u.contains("WITH_WARNINGS")) {
            return "WITH_WARNINGS";
        }
        if (u.contains("RECOMMANDE") || u.contains("RECOMMENDED")) {
            return "RECOMMENDED";
        }
        if (u.contains("INDETERMINE") || u.contains("UNKNOWN")) {
            return "INDETERMINE";
        }
        return u;
    }

    private static int intVal(Map<String, Object> gate, String key) {
        return intObj(gate.get(key), 0);
    }

    private static int firstPresent(Map<String, Object> gate, String... keys) {
        for (String k : keys) {
            if (gate.containsKey(k) && gate.get(k) != null) {
                return intObj(gate.get(k), 0);
            }
        }
        return 0;
    }

    private static String firstString(Map<String, Object> gate, String... keys) {
        for (String k : keys) {
            Object v = gate.get(k);
            if (v != null && !v.toString().isBlank()) {
                return v.toString().trim();
            }
        }
        return null;
    }

    private static int intObj(Object o, int def) {
        if (o == null) {
            return def;
        }
        if (o instanceof Number n) {
            return n.intValue();
        }
        try {
            return Integer.parseInt(o.toString().trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }
}
