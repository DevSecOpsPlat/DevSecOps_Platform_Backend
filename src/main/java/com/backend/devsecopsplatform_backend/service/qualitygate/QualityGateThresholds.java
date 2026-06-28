package com.backend.devsecopsplatform_backend.service.qualitygate;

import java.util.LinkedHashMap;
import java.util.Map;

/** Seuils alignés sur variables CI (.gitlab-ci.yml / pipeline.md). */
public final class QualityGateThresholds {

    public static final int SCA_CRITICAL = 5;
    public static final int SCA_HIGH = 20;
    public static final int CONTAINER_CRITICAL = 0;
    public static final int CONTAINER_HIGH = 10;
    public static final int SEMGREP_HIGH = 10;
    public static final int SEMGREP_MEDIUM = 50;
    public static final int IAC_FAILED = 10;
    public static final int DAST_HIGH = 5;
    public static final int DAST_MEDIUM = 10;
    public static final int SCA_MEDIUM_WARN = 50;

    private QualityGateThresholds() {
    }

    public static Map<String, Object> asMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("scaCritical", SCA_CRITICAL);
        m.put("scaHigh", SCA_HIGH);
        m.put("containerCritical", CONTAINER_CRITICAL);
        m.put("containerHigh", CONTAINER_HIGH);
        m.put("semgrepHigh", SEMGREP_HIGH);
        m.put("semgrepMedium", SEMGREP_MEDIUM);
        m.put("iacFailed", IAC_FAILED);
        m.put("dastHigh", DAST_HIGH);
        m.put("dastMedium", DAST_MEDIUM);
        m.put("secrets", 0);
        return m;
    }
}
