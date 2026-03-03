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

    default PipelineExecution findFirstByUserOrderByCreatedAtDesc(User user) {
        List<PipelineExecution> results = findByUserOrderByCreatedAtDesc(user, PageRequest.of(0, 1));
        return results.isEmpty() ? null : results.get(0);
    }
    Optional<PipelineExecution> findFirstByEnvironmentOrderByCreatedAtDesc(EphemeralEnvironment environment);

    @Query("SELECT pe FROM PipelineExecution pe WHERE pe.environment IN :envs ORDER BY pe.createdAt DESC")
    List<PipelineExecution> findByEnvironmentInOrderByCreatedAtDesc(@Param("envs") List<EphemeralEnvironment> envs, Pageable pageable);
}
