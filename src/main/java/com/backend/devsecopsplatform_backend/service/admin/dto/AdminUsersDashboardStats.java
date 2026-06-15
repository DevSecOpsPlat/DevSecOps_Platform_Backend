package com.backend.devsecopsplatform_backend.service.admin.dto;

import java.util.List;

public record AdminUsersDashboardStats(
        long totalFailedAttempts,
        List<AdminLoginDayStats> loginStatsLast30Days,
        List<AdminSecurityAlert> securityAlerts,
        List<AdminFailedLoginEntry> failedAttemptsDetail
) {}
