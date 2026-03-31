package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.Finding;
import com.backend.devsecopsplatform_backend.entity.FindingStatus;
import com.backend.devsecopsplatform_backend.entity.ScanType;
import com.backend.devsecopsplatform_backend.entity.Severity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface FindingRepository extends JpaRepository<Finding, UUID> {
    Optional<Finding> findByFingerprint(String fingerprint);

    Page<Finding> findByStatus(FindingStatus status, Pageable pageable);

    Page<Finding> findBySeverity(Severity severity, Pageable pageable);

    @Query("""
            select distinct f
            from Finding f
            join FindingOccurrence o on o.finding = f
            join PipelineExecution pe on o.pipelineExecution = pe
            where pe.environment.id = :envId
            order by f.updatedAt desc nulls last, f.createdAt desc
            """)
    Page<Finding> findByEnvironmentId(@Param("envId") UUID envId, Pageable pageable);

    /**
     * Liste paginée pour un environnement avec filtres optionnels (mêmes critères que l’UI).
     * {@code tool} / {@code severity} null ⇒ pas de filtre sur ce champ.
     */
    @Query("""
            select distinct f
            from Finding f
            join FindingOccurrence o on o.finding = f
            join PipelineExecution pe on o.pipelineExecution = pe
            where pe.environment.id = :envId
              and (:tool is null or lower(f.toolName) = lower(:tool))
              and (:severity is null or f.severity = :severity)
            order by f.updatedAt desc nulls last, f.createdAt desc
            """)
    Page<Finding> findByEnvironmentIdFiltered(
            @Param("envId") UUID envId,
            @Param("tool") String tool,
            @Param("severity") Severity severity,
            Pageable pageable);

    @Query("""
            select distinct f
            from Finding f
            join FindingOccurrence o on o.finding = f
            join PipelineExecution pe on o.pipelineExecution = pe
            where pe.gitlabPipelineId = :pipelineId
            order by f.updatedAt desc nulls last, f.createdAt desc
            """)
    Page<Finding> findByGitlabPipelineId(@Param("pipelineId") Long pipelineId, Pageable pageable);

    @Query("""
            select count(distinct f.id)
            from Finding f
            join FindingOccurrence o on o.finding = f
            join PipelineExecution pe on o.pipelineExecution = pe
            where pe.environment.id = :envId
              and f.scanType = :scanType
              and f.status = :status
            """)
    long countDistinctByEnvironmentIdAndScanTypeAndStatus(
            @Param("envId") UUID envId,
            @Param("scanType") ScanType scanType,
            @Param("status") FindingStatus status
    );

    @Query("""
            select distinct f
            from Finding f
            join FindingOccurrence o on o.finding = f
            join PipelineExecution pe on o.pipelineExecution = pe
            where pe.environment.id = :envId
              and f.scanType = :scanType
              and f.status = :status
            order by f.updatedAt desc nulls last, f.createdAt desc
            """)
    Page<Finding> findByEnvironmentIdAndScanTypeAndStatus(
            @Param("envId") UUID envId,
            @Param("scanType") ScanType scanType,
            @Param("status") FindingStatus status,
            Pageable pageable
    );
}

