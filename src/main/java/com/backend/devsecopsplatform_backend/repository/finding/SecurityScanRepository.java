package com.backend.devsecopsplatform_backend.repository.finding;

import com.backend.devsecopsplatform_backend.entity.finding.SecurityScan;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface SecurityScanRepository extends JpaRepository<SecurityScan, UUID> {
    List<SecurityScan> findByPipelineExecutionId(UUID pipelineExecutionId);
}

