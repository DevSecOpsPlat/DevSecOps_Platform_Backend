package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.PipelineStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface PipelineExecutionRepository extends JpaRepository<PipelineExecution, UUID> {

    List<PipelineExecution> findByEnvironmentOrderByCreatedAtDesc(EphemeralEnvironment environment);

    Optional<PipelineExecution> findByGitlabPipelineId(Integer gitlabPipelineId);

    Optional<PipelineExecution> findFirstByEnvironmentOrderByCreatedAtDesc(EphemeralEnvironment environment);
}
