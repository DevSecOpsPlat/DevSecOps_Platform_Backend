package com.backend.devsecopsplatform_backend.service.qualitygate;

import com.backend.devsecopsplatform_backend.service.qualitygate.dto.SecurityScoreDto;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityScoringServiceTest {

    private final SecurityScoringService service = new SecurityScoringService();

    @Test
    void containerCap_appliesWhenCriticalAboveThreshold() {
        Map<String, Integer> dd = new LinkedHashMap<>();
        dd.put("critical", 0);
        dd.put("high", 0);
        dd.put("medium", 0);
        dd.put("low", 0);

        SecurityScoreInput input = SecurityScoreInput.builder()
                .ddBySeverity(dd)
                .secrets(0)
                .containerCritical(3)
                .containerCriticalThreshold(0)
                .scaCriticalThreshold(5)
                .stages(List.of())
                .sonarAvailable(false)
                .build();

        SecurityScoreDto score = service.compute(input);
        assertTrue(score.getScore() <= 50, "container critical > 0 doit plafonner à 50");
        assertTrue(score.getAppliedCaps().contains("cap_container"));
    }
}
