package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.AuditLog;
import com.backend.devsecopsplatform_backend.entity.AuditAction;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.UUID;

public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {

    Page<AuditLog> findAllByOrderByCreatedAtDesc(Pageable pageable);

    Page<AuditLog> findByUserIdOrderByCreatedAtDesc(UUID userId, Pageable pageable);

    Page<AuditLog> findByActionOrderByCreatedAtDesc(AuditAction action, Pageable pageable);

    long countByAction(AuditAction action);

    @Query("SELECT a.action, COUNT(a) FROM AuditLog a GROUP BY a.action")
    java.util.List<Object[]> countGroupByAction();
}
