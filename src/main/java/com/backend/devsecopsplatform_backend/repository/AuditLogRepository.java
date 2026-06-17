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
import java.util.List;
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

    @Query(value = """
            SELECT COUNT(DISTINCT COALESCE(NULLIF(TRIM(username), ''), NULLIF(TRIM(performed_by), '')))
            FROM audit_log
            WHERE created_at >= :since
              AND COALESCE(NULLIF(TRIM(username), ''), NULLIF(TRIM(performed_by), '')) IS NOT NULL
            """, nativeQuery = true)
    long countDistinctActorsSince(@Param("since") LocalDateTime since);

    @Query(value = """
            SELECT actor, cnt, last_at, last_action FROM (
                SELECT COALESCE(NULLIF(TRIM(performed_by), ''), NULLIF(TRIM(username), '')) AS actor,
                       COUNT(*) AS cnt,
                       MAX(created_at) AS last_at,
                       (ARRAY_AGG(action ORDER BY created_at DESC))[1] AS last_action
                FROM audit_log
                WHERE COALESCE(NULLIF(TRIM(performed_by), ''), NULLIF(TRIM(username), '')) IS NOT NULL
                GROUP BY COALESCE(NULLIF(TRIM(performed_by), ''), NULLIF(TRIM(username), ''))
                ORDER BY cnt DESC
                LIMIT :limit
            ) t
            """, nativeQuery = true)
    List<Object[]> topActors(@Param("limit") int limit);

    @Query(value = """
            SELECT date_trunc('hour', created_at) AS hr,
                   SUM(CASE WHEN action = 'LOGIN_SUCCESS' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN action = 'LOGIN_FAILED' THEN 1 ELSE 0 END)
            FROM audit_log
            WHERE created_at >= :since
              AND action IN ('LOGIN_SUCCESS', 'LOGIN_FAILED')
            GROUP BY hr
            ORDER BY hr
            """, nativeQuery = true)
    List<Object[]> loginSuccessFailedByHour(@Param("since") LocalDateTime since);

    @Query(value = """
            SELECT ip_address, MAX(window_failures), MAX(last_at)
            FROM (
                SELECT ip_address,
                       date_trunc('hour', created_at)
                           + floor(extract(minute from created_at) / 5) * interval '5 minutes' AS window_start,
                       COUNT(*) AS window_failures,
                       MAX(created_at) AS last_at
                FROM audit_log
                WHERE action = 'LOGIN_FAILED'
                  AND ip_address IS NOT NULL
                  AND TRIM(ip_address) <> ''
                GROUP BY ip_address, window_start
                HAVING COUNT(*) > :threshold
            ) suspicious_windows
            GROUP BY ip_address
            ORDER BY MAX(window_failures) DESC
            """, nativeQuery = true)
    List<Object[]> suspiciousLoginIpsAllTime(@Param("threshold") int threshold);

    @Query(value = """
            SELECT ip_address, COUNT(*), MAX(created_at)
            FROM audit_log
            WHERE action = 'ACCOUNT_LOCKED'
              AND ip_address IS NOT NULL
              AND TRIM(ip_address) <> ''
            GROUP BY ip_address
            ORDER BY MAX(created_at) DESC
            """, nativeQuery = true)
    List<Object[]> lockedAccountIpsAllTime();

    List<AuditLog> findAllByOrderByCreatedAtDesc();

    List<AuditLog> findByActionOrderByCreatedAtDesc(AuditAction action);

    List<AuditLog> findByActionInOrderByCreatedAtDesc(List<AuditAction> actions);

    @Query(value = """
            SELECT DISTINCT ON (actor) actor, action, details, ip_address, created_at, performed_by
            FROM (
                SELECT COALESCE(NULLIF(TRIM(username), ''), NULLIF(TRIM(performed_by), '')) AS actor,
                       action,
                       details,
                       ip_address,
                       created_at,
                       performed_by
                FROM audit_log
                WHERE COALESCE(NULLIF(TRIM(username), ''), NULLIF(TRIM(performed_by), '')) IS NOT NULL
                ORDER BY actor, created_at DESC
            ) t
            ORDER BY actor, created_at DESC
            """, nativeQuery = true)
    List<Object[]> allActiveUsersLastActivity();
}
