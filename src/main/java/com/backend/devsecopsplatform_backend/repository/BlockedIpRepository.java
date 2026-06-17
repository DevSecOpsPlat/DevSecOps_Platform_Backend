package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.BlockedIp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface BlockedIpRepository extends JpaRepository<BlockedIp, UUID> {

    Optional<BlockedIp> findFirstByIpAddressAndActiveTrueAndBlockedUntilAfter(
            String ipAddress, LocalDateTime now);

    List<BlockedIp> findByActiveTrueAndBlockedUntilAfterOrderByBlockedUntilAsc(LocalDateTime now);

    long countByActiveTrueAndBlockedUntilAfter(LocalDateTime now);

    List<BlockedIp> findTop50ByOrderByCreatedAtDesc();

    @Query("""
            SELECT b FROM BlockedIp b
            WHERE b.createdAt >= :since OR (b.active = true AND b.blockedUntil > :now)
            ORDER BY b.createdAt DESC
            """)
    List<BlockedIp> findForDashboard(@Param("since") LocalDateTime since, @Param("now") LocalDateTime now);

    @Modifying
    @Query("""
            UPDATE BlockedIp b SET b.active = false
            WHERE b.active = true AND b.blockedUntil <= :now
            """)
    int deactivateExpired(@Param("now") LocalDateTime now);

    @Modifying
    @Query("""
            UPDATE BlockedIp b SET b.active = false
            WHERE b.ipAddress = :ipAddress AND b.active = true
            """)
    int deactivateByIpAddress(@Param("ipAddress") String ipAddress);
}
