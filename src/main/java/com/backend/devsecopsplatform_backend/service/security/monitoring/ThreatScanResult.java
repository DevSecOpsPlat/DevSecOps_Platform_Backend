package com.backend.devsecopsplatform_backend.service.security.monitoring;

public record ThreatScanResult(
        ThreatCategory category,
        String detail,
        boolean blockImmediately
) {}
