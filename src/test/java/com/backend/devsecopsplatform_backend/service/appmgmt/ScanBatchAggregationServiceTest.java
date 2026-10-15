package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatch;
import com.backend.devsecopsplatform_backend.service.qualitygate.SecurityScoringService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanBatchAggregationServiceTest {

    private ScanBatchAggregationService aggregation;

    @BeforeEach
    void setUp() {
        aggregation = new ScanBatchAggregationService(new SecurityScoringService());
    }

    @Test
    void hardGateOnOneServiceBlocksAppRegardlessOfOthers() {
        PipelineExecution bad = pe(frontend("front"), gateSecrets(3));
        PipelineExecution good = pe(worker("api"), gateClean());

        var result = aggregation.aggregate(batch(2), List.of(bad, good));

        assertEquals("NOT_RECOMMENDED", result.verdict());
        assertNull(result.securityScore());
        assertNull(result.grade());
        assertTrue(result.services().stream().anyMatch(ScanBatchAggregationService.ServiceContribution::hardGateViolated));
    }

    @Test
    void indeterminateServicePreventsRecommended() {
        PipelineExecution unknown = pe(frontend("front"), gateWithoutSecretsKey());
        PipelineExecution good = pe(worker("api"), gateClean());

        var result = aggregation.aggregate(batch(2), List.of(unknown, good));

        assertEquals("INDETERMINE", result.verdict());
        assertNull(result.securityScore());
    }

    @Test
    void scoreUsesMinNotAverage_publicWeighsMoreThanWorker() {
        // FRONTEND score bas vs WORKER catastrophique brut mais relaxé +10 à la sélection
        PipelineExecution front = pe(frontend("ui"), gateWithFindings(0, 40, 5000));
        PipelineExecution work = pe(worker("job"), gateWithFindings(0, 50, 5000));

        var result = aggregation.aggregate(batch(2), List.of(front, work));

        assertTrue(List.of("RECOMMENDED", "WITH_WARNINGS").contains(result.verdict()));
        assertTrue(result.securityScore() != null);
        int frontScore = result.services().stream()
                .filter(c -> "ui".equals(c.serviceName()))
                .map(ScanBatchAggregationService.ServiceContribution::securityScore)
                .findFirst().orElseThrow();
        int workerScore = result.services().stream()
                .filter(c -> "job".equals(c.serviceName()))
                .map(ScanBatchAggregationService.ServiceContribution::securityScore)
                .findFirst().orElseThrow();
        // Sélection via scores ajustés, report du score réel du service retenu
        int frontAdj = frontScore;
        int workerAdj = Math.min(100, workerScore + ScanBatchAggregationService.WORKER_SCORE_RELAXATION);
        int expectedReal = frontAdj <= workerAdj ? frontScore : workerScore;
        assertEquals(expectedReal, result.securityScore());
        assertEquals(expectedReal, result.payloadExtras().get("dimensioningService") instanceof Map<?, ?> dim
                ? dim.get("securityScore")
                : null);
        assertTrue(result.securityScore() <= frontScore || result.securityScore().equals(workerScore));
    }

    @Test
    void worstVerdictOrdersCorrectly() {
        assertEquals("NOT_RECOMMENDED",
                ScanBatchAggregationService.worstVerdict(List.of("RECOMMENDED", "NOT_RECOMMENDED")));
        assertEquals("INDETERMINE",
                ScanBatchAggregationService.worstVerdict(List.of("RECOMMENDED", "INDETERMINE")));
        assertEquals("WITH_WARNINGS",
                ScanBatchAggregationService.worstVerdict(List.of("RECOMMENDED", "WITH_WARNINGS")));
    }

    private static ScanBatch batch(int expected) {
        ScanBatch b = new ScanBatch();
        b.setExpectedServiceCount(expected);
        return b;
    }

    private static AppService frontend(String name) {
        AppService s = new AppService();
        s.setId(UUID.randomUUID());
        s.setName(name);
        s.setRole(AppServiceRole.FRONTEND);
        s.setExposedPort(80);
        return s;
    }

    private static AppService worker(String name) {
        AppService s = new AppService();
        s.setId(UUID.randomUUID());
        s.setName(name);
        s.setRole(AppServiceRole.WORKER);
        return s;
    }

    private static PipelineExecution pe(AppService svc, Map<String, Object> gate) {
        PipelineExecution pe = new PipelineExecution();
        pe.setId(UUID.randomUUID());
        pe.setAppService(svc);
        pe.setQualityGateJson(gate);
        return pe;
    }

    private static Map<String, Object> gateClean() {
        Map<String, Object> g = new LinkedHashMap<>();
        g.put("secrets", 0);
        g.put("critical", 0);
        g.put("high", 0);
        g.put("scaMedium", 0);
        g.put("containerCritical", 0);
        g.put("sonarQualityGate", "OK");
        g.put("sonarBlockers", 0);
        g.put("sonarCriticals", 0);
        g.put("sonarNcloc", 10000);
        g.put("sonarHotspots", 0);
        return g;
    }

    private static Map<String, Object> gateSecrets(int n) {
        Map<String, Object> g = gateClean();
        g.put("secrets", n);
        return g;
    }

    private static Map<String, Object> gateWithoutSecretsKey() {
        Map<String, Object> g = gateClean();
        g.remove("secrets");
        return g;
    }

    private static Map<String, Object> gateWithFindings(int critical, int high, int ncloc) {
        Map<String, Object> g = gateClean();
        g.put("critical", critical);
        g.put("high", high);
        g.put("sonarNcloc", ncloc);
        return g;
    }
}
