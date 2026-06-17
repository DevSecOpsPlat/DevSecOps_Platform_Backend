package com.backend.devsecopsplatform_backend.service.admin.dto;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.LocalDateTime;
import java.util.List;

public record AdminAuditDashboardResponse(
        AdminAuditEnhancedKpis enhancedKpis,
        List<AdminAuditTopUser> topUsers,
        List<AdminAuditLoginHourPoint> loginComparison,
        AdminAuditAdminVsUsers adminVsUsers,
        List<AdminAuditSuspiciousIp> suspiciousIps,
        List<AdminAuditKpiPanel> kpiPanels
) {

    public record AdminAuditEnhancedKpis(
            double loginSuccessRatePercent,
            String loginSuccessTooltip,
            long activeUsers24h,
            String activeUsersTooltip,
            long adminActionsCount,
            String adminActionsTooltip,
            long suspiciousIpsCount,
            String suspiciousIpsTooltip
    ) {}

    public record AdminAuditTopUser(
            String username,
            long count,
            String tooltip,
            String lastAction,
            @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
            LocalDateTime lastActionAt
    ) {}

    public record AdminAuditLoginHourPoint(
            String hour,
            long success,
            long failed,
            String tooltip
    ) {}

    public record AdminAuditAdminVsUsers(
            long adminActions,
            long userActions,
            double adminPercent,
            String adminTooltip,
            String userTooltip
    ) {}

    public record AdminAuditSuspiciousIp(
            String ip,
            long failureCount,
            String tooltip,
            @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
            LocalDateTime lastFailureAt
    ) {}

    public record AdminAuditKpiPanel(
            String key,
            String title,
            String hoverDescription,
            long count,
            String countHint,
            List<AdminAuditKpiPanelItem> items
    ) {}

    public record AdminAuditKpiPanelItem(
            String line1,
            String line2,
            String line3,
            String ip,
            @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
            LocalDateTime occurredAt
    ) {}
}
