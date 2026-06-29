package com.backend.devsecopsplatform_backend.service.qualitygate;

import com.backend.devsecopsplatform_backend.service.qualitygate.dto.SecurityScoreDto;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityScoringServiceTest {

    private final SecurityScoringService service = new SecurityScoringService();

    @Test
    void hardGate_secretsBlockImmediately() {
        HardGateInput input = HardGateInput.builder()
                .secrets(2)
                .ddCritical(0)
                .sonarBlockers(0)
                .defectDojoAvailable(true)
                .sonarAvailable(true)
                .build();
        var eval = service.evaluateHardGates(input);
        assertEquals(1, eval.violations().size());
        assertTrue(eval.summaryMessage().contains("2 secret"));
    }

    @Test
    void hardGate_defectDojoUnavailableIsIndeterminate() {
        HardGateInput input = HardGateInput.builder()
                .secrets(0)
                .defectDojoAvailable(false)
                .sonarAvailable(true)
                .build();
        var eval = service.evaluateHardGates(input);
        assertTrue(eval.indeterminateSources().contains("Centralisation des vulnérabilités"));
    }

    @Test
    void postureScore_usesDensityWhenNclocKnown() {
        Map<String, Integer> dd = new LinkedHashMap<>();
        dd.put("critical", 0);
        dd.put("high", 20);
        dd.put("medium", 0);
        dd.put("low", 0);

        SecurityScoreInput input = SecurityScoreInput.builder()
                .ddBySeverity(dd)
                .secrets(0)
                .ncloc(10000)
                .stages(List.of())
                .sonarAvailable(true)
                .defectDojoAvailable(true)
                .build();

        SecurityScoreDto score = service.computePostureScore(input);
        assertTrue(score.getScore() < 100, "density penalty should reduce score");
        assertTrue(score.getScore() >= 75);
        assertEquals("RECOMMENDED", score.getDerivedVerdict());
    }
}
