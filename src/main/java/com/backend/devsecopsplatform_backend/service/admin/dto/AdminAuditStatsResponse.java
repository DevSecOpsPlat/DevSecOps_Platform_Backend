package com.backend.devsecopsplatform_backend.service.admin.dto;

import java.util.Map;

public record AdminAuditStatsResponse(
        long totalCount,
        Map<String, Long> countByAction
) {}
