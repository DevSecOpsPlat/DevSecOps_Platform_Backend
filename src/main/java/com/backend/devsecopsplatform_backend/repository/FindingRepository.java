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

import java.util.List;
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
              and (:tool is null or f.toolName = :tool)
              and (:severity is null or f.severity = :severity)
              and (:scanType is null or f.scanType = :scanType)
            order by f.updatedAt desc nulls last, f.createdAt desc
            """)
    Page<Finding> findByEnvironmentIdFiltered(
            @Param("envId") UUID envId,
            @Param("tool") String tool,
            @Param("severity") Severity severity,
            @Param("scanType") ScanType scanType,
            Pageable pageable);

    @Query("""
            select distinct f
            from Finding f
            join FindingOccurrence o on o.finding = f
            join PipelineExecution pe on o.pipelineExecution = pe
            join EphemeralEnvironment env on pe.environment = env
            where env.application.id = :appId
              and (:branch is null or env.gitBranch = :branch)
              and (:tool is null or f.toolName = :tool)
              and (:severity is null or f.severity = :severity)
              and (:scanType is null or f.scanType = :scanType)
              and (:status is null or f.status = :status)
            order by f.updatedAt desc nulls last, f.createdAt desc
            """)
    Page<Finding> findByApplicationFiltered(
            @Param("appId") UUID appId,
            @Param("branch") String branch,
            @Param("tool") String tool,
            @Param("severity") Severity severity,
            @Param("scanType") ScanType scanType,
            @Param("status") FindingStatus status,
            Pageable pageable);

    @Query("""
            select distinct f
            from Finding f
            join FindingOccurrence o on o.finding = f
            join PipelineExecution pe on o.pipelineExecution = pe
            join EphemeralEnvironment env on pe.environment = env
            where env.application.id = :appId
              and env.gitBranch = :branch
              and f.status = :status
              and f.fingerprint not in :currentFingerprints
            """)
    List<Finding> findOpenFindingsForAppBranchNotInFingerprints(
            @Param("appId") UUID appId,
            @Param("branch") String branch,
            @Param("status") FindingStatus status,
            @Param("currentFingerprints") List<String> currentFingerprints);

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
            select distinct f
            from Finding f
            join FindingOccurrence o on o.finding = f
            join PipelineExecution pe on o.pipelineExecution = pe
            where pe.gitlabPipelineId = :pipelineId
              and (:tool is null or f.toolName = :tool)
              and (:severity is null or f.severity = :severity)
              and (:scanType is null or f.scanType = :scanType)
              and (:status is null or f.status = :status)
            order by f.updatedAt desc nulls last, f.createdAt desc
            """)
    Page<Finding> findByGitlabPipelineIdFiltered(
            @Param("pipelineId") Long pipelineId,
            @Param("tool") String tool,
            @Param("severity") Severity severity,
            @Param("scanType") ScanType scanType,
            @Param("status") FindingStatus status,
            Pageable pageable);

    @Query("""
            select distinct f
            from Finding f
            where f.fingerprint in :fingerprints
              and exists (
                  select 1
                  from FindingOccurrence o2
                  join o2.pipelineExecution pe2
                  join pe2.environment env2
                  where o2.finding = f and env2.application.id = :appId
              )
            order by f.updatedAt desc nulls last, f.createdAt desc
            """)
    List<Finding> findDistinctByApplicationIdAndFingerprintIn(
            @Param("appId") UUID appId,
            @Param("fingerprints") List<String> fingerprints);

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

