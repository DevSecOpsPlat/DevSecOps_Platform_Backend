package com.backend.devsecopsplatform_backend.service.security;

import com.backend.devsecopsplatform_backend.entity.admin.Alert;
import com.backend.devsecopsplatform_backend.entity.admin.AlertStatus;
import com.backend.devsecopsplatform_backend.entity.admin.AlertType;
import com.backend.devsecopsplatform_backend.entity.admin.AuditAction;
import com.backend.devsecopsplatform_backend.entity.admin.AuditLog;
import com.backend.devsecopsplatform_backend.entity.user.User;
import com.backend.devsecopsplatform_backend.repository.admin.AlertRepository;
import com.backend.devsecopsplatform_backend.repository.admin.AuditLogRepository;
import com.backend.devsecopsplatform_backend.util.IpAddressUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class SecurityEventService {

    private final AlertRepository alertRepository;
    private final AuditLogRepository auditLogRepository;

    @Transactional
    public void createAlert(AlertType type, String message, User relatedUser, String ipAddress) {
        createAlert(type, message, relatedUser, ipAddress, null);
    }

    @Transactional
    public void createAlert(AlertType type, String message, User relatedUser, String ipAddress, String detailsJson) {
        Alert alert = new Alert();
        alert.setType(type);
        alert.setMessage(message);
        alert.setStatus(AlertStatus.NON_LUE);
        if (relatedUser != null) {
            alert.setRelatedUserId(relatedUser.getId());
            alert.setRelatedUsername(relatedUser.getUsername());
        }
        alert.setIpAddress(IpAddressUtils.normalize(ipAddress));
        alert.setDetailsJson(detailsJson);
        alertRepository.save(alert);
    }

    @Transactional
    public void recordAudit(AuditAction action, User subject, String details, String performedBy, String ipAddress) {
        AuditLog log = new AuditLog();
        if (subject != null) {
            log.setUserId(subject.getId());
            log.setUsername(subject.getUsername());
        }
        log.setAction(action);
        log.setDetails(details);
        log.setPerformedBy(performedBy);
        log.setIpAddress(IpAddressUtils.normalize(ipAddress));
        auditLogRepository.save(log);
    }
}
