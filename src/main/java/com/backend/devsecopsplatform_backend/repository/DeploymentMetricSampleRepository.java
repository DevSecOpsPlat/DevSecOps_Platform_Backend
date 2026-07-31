package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.appmgmt.DeploymentMetricSample;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public interface DeploymentMetricSampleRepository extends JpaRepository<DeploymentMetricSample, UUID> {

    List<DeploymentMetricSample> findByDeploymentIdAndSampledAtBetweenOrderBySampledAtAsc(
            UUID deploymentId, Instant from, Instant to);

    @Modifying(clearAutomatically = true)
    @Query("DELETE FROM DeploymentMetricSample s WHERE s.sampledAt < :before")
    int deleteBySampledAtBefore(@Param("before") Instant before);
}
