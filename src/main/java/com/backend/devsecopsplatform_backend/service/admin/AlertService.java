package com.backend.devsecopsplatform_backend.service.admin;

import com.backend.devsecopsplatform_backend.entity.Alert;
import com.backend.devsecopsplatform_backend.entity.AlertStatus;
import com.backend.devsecopsplatform_backend.entity.AlertType;
import com.backend.devsecopsplatform_backend.repository.AlertRepository;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAlertResponse;
import com.backend.devsecopsplatform_backend.service.admin.dto.AdminAlertStatsResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AlertService {

    private final AlertRepository alertRepository;

    @Transactional(readOnly = true)
    public List<AdminAlertResponse> listAlerts(AlertStatus status, AlertType type) {
        List<Alert> alerts;
        if (status != null && type != null) {
            alerts = alertRepository.findByDeletedFalseAndStatusAndTypeOrderByCreatedAtDesc(status, type);
        } else if (status != null) {
            alerts = alertRepository.findByDeletedFalseAndStatusOrderByCreatedAtDesc(status);
        } else if (type != null) {
            alerts = alertRepository.findByDeletedFalseAndTypeOrderByCreatedAtDesc(type);
        } else {
            alerts = alertRepository.findByDeletedFalseOrderByCreatedAtDesc();
        }
        return alerts.stream().map(this::toResponse).toList();
    }

    @Transactional(readOnly = true)
    public long countUnread() {
        return alertRepository.countByDeletedFalseAndStatus(AlertStatus.NON_LUE);
    }

    @Transactional(readOnly = true)
    public AdminAlertStatsResponse getStats() {
        List<Alert> all = alertRepository.findByDeletedFalseOrderByCreatedAtDesc();
        long unread = all.stream().filter(a -> a.getStatus() == AlertStatus.NON_LUE).count();
        Map<String, Long> byType = new LinkedHashMap<>();
        for (AlertType t : AlertType.values()) {
            byType.put(t.name(), 0L);
        }
        for (Alert a : all) {
            byType.merge(a.getType().name(), 1L, Long::sum);
        }
        return new AdminAlertStatsResponse(unread, all.size(), byType);
    }

    @Transactional
    public AdminAlertResponse markAsRead(UUID id) {
        Alert alert = findOrThrow(id);
        alert.setStatus(AlertStatus.LUE);
        return toResponse(alertRepository.save(alert));
    }

    @Transactional
    public void softDelete(UUID id) {
        Alert alert = findOrThrow(id);
        alert.setDeleted(true);
        alertRepository.save(alert);
    }

    private Alert findOrThrow(UUID id) {
        return alertRepository.findById(id)
                .filter(a -> !a.isDeleted())
                .orElseThrow(() -> new IllegalArgumentException("Alerte introuvable."));
    }

    private AdminAlertResponse toResponse(Alert a) {
        return new AdminAlertResponse(
                a.getId(),
                a.getType().name(),
                a.getMessage(),
                a.getStatus().name(),
                a.getRelatedUserId(),
                a.getRelatedUsername(),
                a.getIpAddress(),
                a.getCreatedAt()
        );
    }
}
