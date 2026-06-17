package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.Alert;
import com.backend.devsecopsplatform_backend.entity.AlertStatus;
import com.backend.devsecopsplatform_backend.entity.AlertType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

public interface AlertRepository extends JpaRepository<Alert, UUID>, JpaSpecificationExecutor<Alert> {

    List<Alert> findByDeletedFalseOrderByCreatedAtDesc();

    List<Alert> findByDeletedFalseAndStatusOrderByCreatedAtDesc(AlertStatus status);

    List<Alert> findByDeletedFalseAndTypeOrderByCreatedAtDesc(AlertType type);

    List<Alert> findByDeletedFalseAndStatusAndTypeOrderByCreatedAtDesc(AlertStatus status, AlertType type);

    long countByDeletedFalseAndStatus(AlertStatus status);

    long countByDeletedFalseAndCreatedAtAfter(LocalDateTime since);

    long countByDeletedFalseAndTypeAndCreatedAtAfter(AlertType type, LocalDateTime since);

    @Query(value = """
            SELECT date_trunc('hour', created_at) AS hr, COUNT(*)
            FROM alerts
            WHERE deleted = false AND created_at >= :since
            GROUP BY hr
            ORDER BY hr
            """, nativeQuery = true)
    List<Object[]> countByHourSince(@Param("since") LocalDateTime since);

    @Query(value = """
            SELECT ip_address, COUNT(*) AS cnt
            FROM alerts
            WHERE deleted = false AND created_at >= :since AND ip_address IS NOT NULL
            GROUP BY ip_address
            ORDER BY cnt DESC
            LIMIT :limit
            """, nativeQuery = true)
    List<Object[]> topIpsSince(@Param("since") LocalDateTime since, @Param("limit") int limit);

    List<Alert> findTop1ByDeletedFalseAndIpAddressAndCreatedAtAfterOrderByCreatedAtDesc(
            String ipAddress, LocalDateTime since);
}
