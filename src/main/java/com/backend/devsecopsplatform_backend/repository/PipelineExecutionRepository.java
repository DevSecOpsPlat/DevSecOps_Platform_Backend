package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.PipelineStatus;
import com.backend.devsecopsplatform_backend.entity.User;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface PipelineExecutionRepository extends JpaRepository<PipelineExecution, UUID> {

    List<PipelineExecution> findByEnvironmentOrderByCreatedAtDesc(EphemeralEnvironment environment);

    Optional<PipelineExecution> findByGitlabPipelineId(Long gitlabPipelineId);

    @Query("SELECT p FROM PipelineExecution p " +
            "WHERE p.environment.requestedBy = :user " +
            "ORDER BY p.createdAt DESC")
    List<PipelineExecution> findByUserOrderByCreatedAtDesc(User user, Pageable pageable);

    @Query("select count(pe) from PipelineExecution pe where pe.environment.requestedBy = :user")
    long countByUser(@Param("user") User user);

    @Query("select count(pe) from PipelineExecution pe where pe.environment.requestedBy = :user and pe.status = :status")
    long countByUserAndStatus(@Param("user") User user, @Param("status") PipelineStatus status);

    @Query("select pe.status, count(pe) from PipelineExecution pe where pe.environment.requestedBy = :user group by pe.status")
    List<Object[]> countByUserGroupByStatus(@Param("user") User user);

    @Query("""
            select pe.environment.application.id, pe.status, count(pe)
            from PipelineExecution pe
            where pe.environment.requestedBy = :user
            group by pe.environment.application.id, pe.status
            """)
    List<Object[]> countByUserGroupByApplicationAndStatus(@Param("user") User user);

    default PipelineExecution findFirstByUserOrderByCreatedAtDesc(User user) {
        List<PipelineExecution> results = findByUserOrderByCreatedAtDesc(user, PageRequest.of(0, 1));
        return results.isEmpty() ? null : results.get(0);
    }
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
            join pe.environment env
            where env.application.id = :appId
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
            join pe.environment env
            where env.application.id = :appId
              and (:branch is null or env.gitBranch = :branch)
              and pe.gitlabPipelineId is not null
            order by pe.createdAt desc
            """)
    List<Long> findGitlabPipelineIdsByApplicationIdAndBranchOrderByCreatedAtDesc(
            @Param("appId") UUID appId,
            @Param("branch") String branch,
            Pageable pageable
    );
}
