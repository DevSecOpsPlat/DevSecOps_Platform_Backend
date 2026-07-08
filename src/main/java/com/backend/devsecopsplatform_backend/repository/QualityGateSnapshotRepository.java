package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.QualityGateSnapshot;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface QualityGateSnapshotRepository extends JpaRepository<QualityGateSnapshot, UUID> {

    Optional<QualityGateSnapshot> findFirstByEnvironmentIdOrderByCreatedAtDesc(UUID environmentId);

    Optional<QualityGateSnapshot> findFirstByApplicationIdAndBranchOrderByCreatedAtDesc(
            UUID applicationId, String branch);

    Optional<QualityGateSnapshot> findFirstByApplicationIdOrderByCreatedAtDesc(UUID applicationId);

    Optional<QualityGateSnapshot> findByPipelineExecutionId(UUID pipelineExecutionId);

    Optional<QualityGateSnapshot> findByGitlabPipelineId(Long gitlabPipelineId);

    java.util.List<QualityGateSnapshot> findAllByApplicationIdAndBranchOrderByCreatedAtDesc(
            UUID applicationId, String branch);

    java.util.List<QualityGateSnapshot> findAllByEnvironmentIdOrderByCreatedAtDesc(UUID environmentId);
}
