package com.backend.devsecopsplatform_backend.service.admin.dto;

import java.util.Map;

public record AdminAlertStatsResponse(
        long unreadCount,
        long totalCount,
        Map<String, Long> countByType
) {}
