package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.FindingOccurrence;
import com.backend.devsecopsplatform_backend.entity.ScanType;
import com.backend.devsecopsplatform_backend.entity.Severity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Map;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface FindingOccurrenceRepository extends JpaRepository<FindingOccurrence, UUID> {

    long countByFinding_IdAndPipelineExecution_Environment_Id(UUID findingId, UUID environmentId);

    Optional<FindingOccurrence> findFirstByFinding_IdOrderByObservedAtDesc(UUID findingId);

    @Query("""
            select o from FindingOccurrence o
            where o.pipelineExecution.gitlabPipelineId = :pipelineId
            """)
    List<FindingOccurrence> findByGitlabPipelineId(@Param("pipelineId") Long pipelineId);

    @Query("""
            select f.severity as severity, count(distinct f.id) as cnt
            from FindingOccurrence o
            join o.finding f
            join o.pipelineExecution pe
            where pe.environment.id = :envId
            group by f.severity
            """)
    List<Object[]> countDistinctFindingsBySeverityForEnv(@Param("envId") UUID envId);

    @Query("""
            select f.scanType as scanType, count(distinct f.id) as cnt
            from FindingOccurrence o
            join o.finding f
            join o.pipelineExecution pe
            where pe.environment.id = :envId
            group by f.scanType
            """)
    List<Object[]> countDistinctFindingsByScanTypeForEnv(@Param("envId") UUID envId);

    @Query("""
            select f.toolName as tool, count(distinct f.id) as cnt
            from FindingOccurrence o
            join o.finding f
            join o.pipelineExecution pe
            where pe.environment.id = :envId
            group by f.toolName
            """)
    List<Object[]> countDistinctFindingsByToolForEnv(@Param("envId") UUID envId);

    @Query("""
            select f.severity as severity, count(distinct f.id) as cnt
            from FindingOccurrence o
            join o.finding f
            where o.pipelineExecution.gitlabPipelineId = :pipelineId
            group by f.severity
            """)
    List<Object[]> countDistinctFindingsBySeverityForPipeline(@Param("pipelineId") Long pipelineId);

    @Query("""
            select f.scanType as scanType, count(distinct f.id) as cnt
            from FindingOccurrence o
            join o.finding f
            where o.pipelineExecution.gitlabPipelineId = :pipelineId
            group by f.scanType
            """)
    List<Object[]> countDistinctFindingsByScanTypeForPipeline(@Param("pipelineId") Long pipelineId);

    @Query("""
            select f.toolName as tool, count(distinct f.id) as cnt
            from FindingOccurrence o
            join o.finding f
            where o.pipelineExecution.gitlabPipelineId = :pipelineId
            group by f.toolName
            """)
    List<Object[]> countDistinctFindingsByToolForPipeline(@Param("pipelineId") Long pipelineId);

    @Query("""
            select distinct f.fingerprint
            from FindingOccurrence o
            join o.finding f
            where o.pipelineExecution.gitlabPipelineId = :pipelineId
            """)
    List<String> findDistinctFingerprintsByPipeline(@Param("pipelineId") Long pipelineId);

    @Query("""
            select o
            from FindingOccurrence o
            join fetch o.finding f
            join o.pipelineExecution pe
            join pe.environment env
            join env.requestedBy u
            where u.username = :username
            order by o.observedAt desc
            """)
    List<FindingOccurrence> findRecentForUsername(@Param("username") String username, org.springframework.data.domain.Pageable pageable);
}

