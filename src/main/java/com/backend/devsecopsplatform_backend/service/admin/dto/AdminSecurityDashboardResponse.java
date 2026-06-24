package com.backend.devsecopsplatform_backend.service.admin.dto;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.LocalDateTime;
import java.util.List;

public record AdminSecurityDashboardResponse(
        AdminSecurityKpis kpis,
        List<AdminKpiPanel> kpiPanels,
        List<AdminBlockedIpDetail> blockedIps,
        List<AdminAlertHourPoint> hourlyTrend,
        List<AdminAlertTypeSlice> typeDistribution,
        List<AdminTopMaliciousIp> topIps
) {

    public record AdminSecurityKpis(
            long alertsTotal,
            long blockedIpsActive,
            long bruteForceTotal,
            long honeypotTotal,
            long rateLimitTotal,
            long xssSqlTotal,
            long ddosLikeTotal
    ) {}

    public record AdminKpiPanel(
            String key,
            String title,
            String hoverDescription,
            long count,
            String countHint,
            List<AdminKpiPanelItem> items
    ) {}

    public record AdminKpiPanelItem(
            String line1,
            String line2,
            String line3,
            String ip,
            @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
            LocalDateTime occurredAt
    ) {}

    public record AdminBlockedIpDetail(
            String ip,
            String reason,
            String source,
            boolean currentlyActive,
            @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
            LocalDateTime blockedUntil,
            @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
            LocalDateTime createdAt
    ) {}

    public record AdminAlertHourPoint(
            String hour,
            long count,
            String tooltip
    ) {}

    public record AdminAlertTypeSlice(
            String type,
            String label,
            long count,
            String tooltip
    ) {}

    public record AdminTopMaliciousIp(
            String ip,
            long count,
            String tooltip,
            String lastActivity
    ) {}
}
