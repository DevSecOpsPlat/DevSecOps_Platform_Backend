package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.Alert;
import com.backend.devsecopsplatform_backend.entity.AlertStatus;
import com.backend.devsecopsplatform_backend.entity.AlertType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface AlertRepository extends JpaRepository<Alert, UUID> {

    List<Alert> findByDeletedFalseOrderByCreatedAtDesc();

    List<Alert> findByDeletedFalseAndStatusOrderByCreatedAtDesc(AlertStatus status);

    List<Alert> findByDeletedFalseAndTypeOrderByCreatedAtDesc(AlertType type);

    List<Alert> findByDeletedFalseAndStatusAndTypeOrderByCreatedAtDesc(AlertStatus status, AlertType type);

    long countByDeletedFalseAndStatus(AlertStatus status);
}
