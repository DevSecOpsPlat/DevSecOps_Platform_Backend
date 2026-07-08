package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.PipelineExecutionKind;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.entity.PipelineStatus;
import org.springframework.data.domain.PageRequest;
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
public interface PipelineExecutionRepository extends JpaRepository<PipelineExecution, UUID> {

    List<PipelineExecution> findByEnvironmentOrderByCreatedAtDesc(EphemeralEnvironment environment);

    Optional<PipelineExecution> findByGitlabPipelineId(Long gitlabPipelineId);

    List<PipelineExecution> findByStatusIn(Collection<PipelineStatus> statuses);

    @Query("""
            SELECT pe FROM PipelineExecution pe
            JOIN FETCH pe.appService app
            LEFT JOIN FETCH app.createdBy
            LEFT JOIN FETCH pe.environment env
            LEFT JOIN FETCH env.requestedBy
            WHERE pe.gitlabPipelineId = :pipelineId
              AND app.id = :appId
            """)
    Optional<PipelineExecution> findByGitlabPipelineIdAndApplicationId(
            @Param("pipelineId") Long pipelineId,
            @Param("appId") UUID appId
    );

    @Query("""
            SELECT pe FROM PipelineExecution pe
            JOIN FETCH pe.appService app
            LEFT JOIN FETCH app.createdBy
            LEFT JOIN FETCH pe.environment env
            LEFT JOIN FETCH env.requestedBy
            WHERE pe.id = :id
            """)
    Optional<PipelineExecution> findByIdWithDetailsForSnapshot(@Param("id") UUID id);

    @Query("SELECT p FROM PipelineExecution p " +
            "WHERE p.appService.createdBy = :user " +
            "ORDER BY p.createdAt DESC")
    List<PipelineExecution> findByUserOrderByCreatedAtDesc(User user, Pageable pageable);

    @Query("select count(pe) from PipelineExecution pe where pe.appService.createdBy = :user")
    long countByUser(@Param("user") User user);

    @Query("select count(pe) from PipelineExecution pe where pe.appService.createdBy = :user and pe.status = :status")
    long countByUserAndStatus(@Param("user") User user, @Param("status") PipelineStatus status);

    @Query("select pe.status, count(pe) from PipelineExecution pe where pe.appService.createdBy = :user group by pe.status")
    List<Object[]> countByUserGroupByStatus(@Param("user") User user);

    @Query("""
            select pe.appService.id, pe.status, count(pe)
            from PipelineExecution pe
            where pe.appService.createdBy = :user
            group by pe.appService.id, pe.status
            """)
    List<Object[]> countByUserGroupByApplicationAndStatus(@Param("user") User user);

    default PipelineExecution findFirstByUserOrderByCreatedAtDesc(User user) {
        List<PipelineExecution> results = findByUserOrderByCreatedAtDesc(user, PageRequest.of(0, 1));
        return results.isEmpty() ? null : results.get(0);
    }

    @Query("""
            SELECT pe FROM PipelineExecution pe
            JOIN pe.appService app
            WHERE app.createdBy = :user
              AND (:applicationId IS NULL OR app.id = :applicationId)
              AND (:kind IS NULL OR pe.executionKind = :kind)
            ORDER BY pe.createdAt DESC
            """)
    List<PipelineExecution> findByUserAndFiltersOrderByCreatedAtDesc(
            @Param("user") User user,
            @Param("applicationId") UUID applicationId,
            @Param("kind") PipelineExecutionKind kind,
            Pageable pageable
    );
    Optional<PipelineExecution> findFirstByEnvironmentOrderByCreatedAtDesc(EphemeralEnvironment environment);

    @Query("SELECT pe FROM PipelineExecution pe WHERE pe.environment IN :envs ORDER BY pe.createdAt DESC")
    List<PipelineExecution> findByEnvironmentInOrderByCreatedAtDesc(@Param("envs") List<EphemeralEnvironment> envs, Pageable pageable);

    @Query("""
            select pe.gitlabPipelineId
            from PipelineExecution pe
            where pe.environment.id = :envId
              and pe.gitlabPipelineId is not null
            order by pe.createdAt desc
            """)
    List<Long> findGitlabPipelineIdsByEnvironmentIdOrderByCreatedAtDesc(@Param("envId") UUID envId, Pageable pageable);

    @Query("""
            select pe.gitlabPipelineId
            from PipelineExecution pe
            where pe.appService.id = :appId
              and pe.gitlabPipelineId is not null
            order by pe.createdAt desc
            """)
    List<Long> findGitlabPipelineIdsByApplicationIdOrderByCreatedAtDesc(
            @Param("appId") UUID appId,
            Pageable pageable
    );

    @Query("""
            select pe.gitlabPipelineId
            from PipelineExecution pe
            where pe.appService.id = :appId
              and (:branch is null or pe.gitBranch = :branch)
              and pe.gitlabPipelineId is not null
            order by pe.createdAt desc
            """)
    List<Long> findGitlabPipelineIdsByApplicationIdAndBranchOrderByCreatedAtDesc(
            @Param("appId") UUID appId,
            @Param("branch") String branch,
            Pageable pageable
    );

    @Query("""
            select count(pe)
            from PipelineExecution pe
            where pe.appService.id = :appId
              and (:branch is null or pe.gitBranch = :branch)
            """)
    long countByApplicationIdAndBranch(@Param("appId") UUID appId, @Param("branch") String branch);

    @Query("""
            select pe.status, count(pe)
            from PipelineExecution pe
            where pe.appService.id = :appId
              and (:branch is null or pe.gitBranch = :branch)
            group by pe.status
            """)
    List<Object[]> countByApplicationIdAndBranchGroupByStatus(
            @Param("appId") UUID appId,
            @Param("branch") String branch
    );

    @Query("""
            select count(pe)
            from PipelineExecution pe
            where pe.appService.id = :appId
            """)
    long countByApplicationId(@Param("appId") UUID appId);

    @Query("""
            select pe.status, count(pe)
            from PipelineExecution pe
            where pe.appService.id = :appId
            group by pe.status
            """)
    List<Object[]> countByApplicationIdGroupByStatus(@Param("appId") UUID appId);

    @Query("""
            SELECT pe FROM PipelineExecution pe
            LEFT JOIN FETCH pe.environment env
            WHERE pe.appService.id = :appId
              AND (:branch IS NULL OR pe.gitBranch = :branch)
            ORDER BY pe.createdAt DESC
            """)
    List<PipelineExecution> findByApplicationIdAndBranchOrderByCreatedAtDesc(
            @Param("appId") UUID appId,
            @Param("branch") String branch,
            Pageable pageable
    );

    @Query("""
            SELECT pe FROM PipelineExecution pe
            WHERE pe.appService.id = :appId
              AND (:branch IS NULL OR pe.gitBranch = :branch)
              AND pe.executionKind = :kind
              AND pe.gitlabPipelineId IS NOT NULL
            ORDER BY pe.createdAt DESC
            """)
    List<PipelineExecution> findByApplicationIdAndBranchAndExecutionKindOrderByCreatedAtDesc(
            @Param("appId") UUID appId,
            @Param("branch") String branch,
            @Param("kind") PipelineExecutionKind kind,
            Pageable pageable
    );

    @Query("""
            SELECT pe FROM PipelineExecution pe
            JOIN FETCH pe.environment env
            WHERE env.id = :environmentId
              AND env.service.id = :appId
            """)
    Optional<PipelineExecution> findByEnvironmentIdAndApplicationId(
            @Param("environmentId") UUID environmentId,
            @Param("appId") UUID appId
    );

    @Query("""
            SELECT pe FROM PipelineExecution pe
            JOIN FETCH pe.environment env
            JOIN FETCH env.service app
            LEFT JOIN FETCH app.createdBy
            LEFT JOIN FETCH env.requestedBy
            WHERE env.id = :environmentId
              AND app.id = :appId
            """)
    Optional<PipelineExecution> findByEnvironmentIdAndApplicationIdWithDetails(
            @Param("environmentId") UUID environmentId,
            @Param("appId") UUID appId
    );

    @Query("""
            SELECT pe FROM PipelineExecution pe
            JOIN FETCH pe.environment env
            JOIN FETCH env.service app
            WHERE pe.id = :id
            """)
    Optional<PipelineExecution> findByIdWithEnvironmentAndService(@Param("id") UUID id);

    /** Pipeline CI snapshot : env + app + utilisateurs (évite lazy-load hors session). */
    @Query("""
            SELECT pe FROM PipelineExecution pe
            JOIN FETCH pe.environment env
            JOIN FETCH env.service app
            LEFT JOIN FETCH app.createdBy
            LEFT JOIN FETCH env.requestedBy
            WHERE env.id = :environmentId
            """)
    Optional<PipelineExecution> findByEnvironmentIdWithDetails(@Param("environmentId") UUID environmentId);
}
