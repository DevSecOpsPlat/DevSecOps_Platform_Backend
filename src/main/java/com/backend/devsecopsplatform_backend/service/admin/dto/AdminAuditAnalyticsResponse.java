package com.backend.devsecopsplatform_backend.service.admin.dto;

import java.util.List;

public record AdminAuditAnalyticsResponse(
        long totalCount,
        List<AdminAuditDayCount> dailyTrend,
        List<AdminAuditDayCount> monthlyTrend,
        List<AdminAuditDayCount> allTimeTrend,
        List<AdminAuditTopActor> topAdmins
) {}
