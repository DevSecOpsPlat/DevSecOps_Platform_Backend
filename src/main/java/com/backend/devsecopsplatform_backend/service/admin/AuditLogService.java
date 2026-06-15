package com.backend.devsecopsplatform_backend.service.admin;

import com.backend.devsecopsplatform_backend.entity.AuditAction;
import com.backend.devsecopsplatform_backend.entity.AuditLog;
import com.backend.devsecopsplatform_backend.repository.AuditLogRepository;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditLogResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditPageResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAuditStatsResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;

    @Transactional(readOnly = true)
    public AdminAuditPageResponse getPage(int page, int size, UUID userId, AuditAction action) {
        Pageable pageable = PageRequest.of(Math.max(page, 0), Math.min(Math.max(size, 1), 100));
        Page<AuditLog> result;
        if (userId != null) {
            result = auditLogRepository.findByUserIdOrderByCreatedAtDesc(userId, pageable);
        } else if (action != null) {
            result = auditLogRepository.findByActionOrderByCreatedAtDesc(action, pageable);
        } else {
            result = auditLogRepository.findAllByOrderByCreatedAtDesc(pageable);
        }
        return new AdminAuditPageResponse(
                result.getContent().stream().map(this::toResponse).toList(),
                result.getTotalElements(),
                result.getTotalPages(),
                result.getNumber(),
                result.getSize()
        );
    }

    @Transactional(readOnly = true)
    public AdminAuditStatsResponse getStats() {
        Map<String, Long> byAction = new LinkedHashMap<>();
        for (AuditAction action : AuditAction.values()) {
            byAction.put(action.name(), 0L);
        }
        for (Object[] row : auditLogRepository.countGroupByAction()) {
            AuditAction action = (AuditAction) row[0];
            long count = ((Number) row[1]).longValue();
            byAction.put(action.name(), count);
        }
        long total = byAction.values().stream().mapToLong(Long::longValue).sum();
        return new AdminAuditStatsResponse(total, byAction);
    }

    private AdminAuditLogResponse toResponse(AuditLog log) {
        return new AdminAuditLogResponse(
                log.getId(),
                log.getCreatedAt(),
                log.getUsername(),
                log.getUserId(),
                log.getAction().name(),
                log.getDetails(),
                log.getPerformedBy(),
                log.getIpAddress()
        );
    }
}
