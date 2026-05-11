package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.FindingOccurrence;
import com.backend.devsecopsplatform_backend.entity.FindingStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface FindingOccurrenceRepository extends JpaRepository<FindingOccurrence, UUID> {

    long countByFinding_IdAndPipelineExecution_Environment_Id(UUID findingId, UUID environmentId);

    Optional<FindingOccurrence> findFirstByFinding_IdOrderByObservedAtDesc(UUID findingId);

    @Query("""
            select count(o.id)
            from FindingOccurrence o
            join o.pipelineExecution pe
            join pe.environment env
            where o.finding.id = :findingId
              and env.application.id = :appId
            """)
    long countByFindingIdAndApplicationId(@Param("findingId") UUID findingId, @Param("appId") UUID appId);

    @Query("""
            select o
            from FindingOccurrence o
            join o.pipelineExecution pe
            join pe.environment env
            where o.finding.id = :findingId
              and env.application.id = :appId
            order by o.observedAt desc
            """)
    List<FindingOccurrence> findByFindingIdAndApplicationIdOrderByObservedAtDesc(@Param("findingId") UUID findingId, @Param("appId") UUID appId);

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

    /** Findings distincts par sévérité pour une application ; {@code status} null = tous les statuts. */
    @Query("""
            select f.severity as severity, count(distinct f.id) as cnt
            from FindingOccurrence o
            join o.finding f
            join o.pipelineExecution pe
            join pe.environment env
            where env.application.id = :appId
              and (:status is null or f.status = :status)
            group by f.severity
            """)
    List<Object[]> countDistinctFindingsBySeverityForApplication(
            @Param("appId") UUID appId,
            @Param("status") FindingStatus status);

    @Query("""
            select f.scanType as scanType, count(distinct f.id) as cnt
            from FindingOccurrence o
            join o.finding f
            join o.pipelineExecution pe
            join pe.environment env
            where env.application.id = :appId
              and (:status is null or f.status = :status)
            group by f.scanType
            """)
    List<Object[]> countDistinctFindingsByScanTypeForApplication(
            @Param("appId") UUID appId,
            @Param("status") FindingStatus status);

    @Query("""
            select f.toolName as tool, count(distinct f.id) as cnt
            from FindingOccurrence o
            join o.finding f
            join o.pipelineExecution pe
            join pe.environment env
            where env.application.id = :appId
              and (:status is null or f.status = :status)
            group by f.toolName
            """)
    List<Object[]> countDistinctFindingsByToolForApplication(
            @Param("appId") UUID appId,
            @Param("status") FindingStatus status);

    @Query("""
            select o
            from FindingOccurrence o
            join fetch o.finding f
            join o.pipelineExecution pe
            join pe.environment env
            join env.requestedBy u
            where u.username = :username
              and env.application.id = :appId
            order by o.observedAt desc
            """)
    List<FindingOccurrence> findRecentForUsernameAndApplication(
            @Param("username") String username,
            @Param("appId") UUID appId,
            org.springframework.data.domain.Pageable pageable);

    @Query("""
            select o
            from FindingOccurrence o
            join fetch o.finding f
            join o.pipelineExecution pe
            join pe.environment env
            join env.requestedBy u
            where u.username = :username
              and env.id = :envId
            order by o.observedAt desc
            """)
    List<FindingOccurrence> findRecentForUsernameAndEnvironment(
            @Param("username") String username,
            @Param("envId") UUID envId,
            org.springframework.data.domain.Pageable pageable);
}

