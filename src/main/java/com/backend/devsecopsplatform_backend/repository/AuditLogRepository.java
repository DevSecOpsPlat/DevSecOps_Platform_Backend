package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.AuditLog;
import com.backend.devsecopsplatform_backend.entity.AuditAction;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.UUID;

public interface AuditLogRepository extends JpaRepository<AuditLog, UUID>, JpaSpecificationExecutor<AuditLog> {

    Page<AuditLog> findAllByOrderByCreatedAtDesc(Pageable pageable);

    Page<AuditLog> findByUserIdOrderByCreatedAtDesc(UUID userId, Pageable pageable);

    Page<AuditLog> findByActionOrderByCreatedAtDesc(AuditAction action, Pageable pageable);

    long countByAction(AuditAction action);

    @Query("SELECT a.action, COUNT(a) FROM AuditLog a GROUP BY a.action")
    java.util.List<Object[]> countGroupByAction();

    @Query(value = """
            SELECT CAST(created_at AS date) AS day, COUNT(*)
            FROM audit_log
            WHERE created_at >= :since
            GROUP BY CAST(created_at AS date)
            ORDER BY day
            """, nativeQuery = true)
    java.util.List<Object[]> countByDaySince(@Param("since") LocalDateTime since);

    @Query(value = """
            SELECT DATE_TRUNC('month', created_at)::date AS month, COUNT(*)
            FROM audit_log
            WHERE created_at >= :since
            GROUP BY DATE_TRUNC('month', created_at)
            ORDER BY month
            """, nativeQuery = true)
    java.util.List<Object[]> countByMonthSince(@Param("since") LocalDateTime since);

    @Query(value = """
            SELECT DATE_TRUNC('month', created_at)::date AS month, COUNT(*)
            FROM audit_log
            GROUP BY DATE_TRUNC('month', created_at)
            ORDER BY month
            """, nativeQuery = true)
    java.util.List<Object[]> countAllByMonth();

    @Query(value = """
            SELECT a.performed_by, COUNT(*)
            FROM audit_log a
            INNER JOIN users u ON LOWER(TRIM(u.username)) = LOWER(TRIM(a.performed_by))
            INNER JOIN user_roles ur ON ur.user_id = u.id AND ur.roles = 'ROLE_ADMIN'
            WHERE a.performed_by IS NOT NULL
              AND TRIM(a.performed_by) <> ''
              AND a.action IN (
                'ACCOUNT_CREATED', 'ACCOUNT_DELETED', 'ACCOUNT_ENABLED', 'ACCOUNT_DISABLED',
                'ADMIN_PASSWORD_RESET', 'ADMIN_EMAIL_CHANGED', 'ACTIVATION_EMAIL_SENT'
              )
            GROUP BY a.performed_by
            ORDER BY COUNT(*) DESC
            LIMIT 3
            """, nativeQuery = true)
    java.util.List<Object[]> topAdminPerformers();
}
