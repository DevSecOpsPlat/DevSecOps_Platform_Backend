package com.backend.devsecopsplatform_backend.repository.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatch;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatchStatus;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ScanBatchRepository extends JpaRepository<ScanBatch, UUID> {

    List<ScanBatch> findByManagedApplicationIdOrderByCreatedAtDesc(UUID managedApplicationId, Pageable pageable);

    /** Suppression d'application : managed_application_id est NOT NULL ici, non couvert par le
     * cascade JPA de ManagedApplication (services/databases/deployments seulement). */
    void deleteByManagedApplication_Id(UUID applicationId);

    Optional<ScanBatch> findByIdAndManagedApplicationId(UUID id, UUID managedApplicationId);

    Optional<ScanBatch> findByGitlabPipelineId(Long gitlabPipelineId);

    @Query("""
            SELECT b FROM ScanBatch b
            JOIN FETCH b.managedApplication app
            LEFT JOIN FETCH b.triggeredBy
            WHERE b.id = :id
            """)
    Optional<ScanBatch> findByIdWithDetails(@Param("id") UUID id);

    @Query("""
            SELECT b FROM ScanBatch b
            JOIN FETCH b.managedApplication app
            LEFT JOIN FETCH b.triggeredBy
            WHERE b.id = :id AND app.id = :appId
            """)
    Optional<ScanBatch> findByIdAndAppIdWithDetails(
            @Param("id") UUID id,
            @Param("appId") UUID appId
    );

    @Query("""
            SELECT b FROM ScanBatch b
            WHERE b.managedApplication.id = :appId
              AND b.status = :status
            ORDER BY b.createdAt DESC
            """)
    List<ScanBatch> findByAppIdAndStatusOrderByCreatedAtDesc(
            @Param("appId") UUID appId,
            @Param("status") ScanBatchStatus status,
            Pageable pageable
    );

    /**
     * Dernier lot COMPLETE pour une application (verdict courant — Chantier 2).
     */
    @Query("""
            SELECT b FROM ScanBatch b
            WHERE b.managedApplication.id = :appId
              AND b.status = com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatchStatus.COMPLETE
            ORDER BY b.createdAt DESC
            """)
    List<ScanBatch> findLatestCompleteByAppId(@Param("appId") UUID appId, Pageable pageable);

    List<ScanBatch> findByStatusIn(Collection<ScanBatchStatus> statuses);

    @Query("""
            SELECT b FROM ScanBatch b
            WHERE b.managedApplication.id = :appId
              AND b.status IN :statuses
            ORDER BY b.createdAt DESC
            """)
    List<ScanBatch> findByAppIdAndStatusIn(
            @Param("appId") UUID appId,
            @Param("statuses") Collection<ScanBatchStatus> statuses
    );
}
