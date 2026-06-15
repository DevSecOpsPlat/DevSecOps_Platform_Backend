package com.backend.devsecopsplatform_backend.service.security;

import com.backend.devsecopsplatform_backend.entity.Alert;
import com.backend.devsecopsplatform_backend.entity.AlertStatus;
import com.backend.devsecopsplatform_backend.entity.AlertType;
import com.backend.devsecopsplatform_backend.entity.AuditAction;
import com.backend.devsecopsplatform_backend.entity.AuditLog;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.AlertRepository;
import com.backend.devsecopsplatform_backend.repository.AuditLogRepository;
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
        Alert alert = new Alert();
        alert.setType(type);
        alert.setMessage(message);
        alert.setStatus(AlertStatus.NON_LUE);
        if (relatedUser != null) {
            alert.setRelatedUserId(relatedUser.getId());
            alert.setRelatedUsername(relatedUser.getUsername());
        }
        alert.setIpAddress(IpAddressUtils.normalize(ipAddress));
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
