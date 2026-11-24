package com.backend.devsecopsplatform_backend.repository.environment;

import com.backend.devsecopsplatform_backend.entity.environment.CloudResource;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface CloudResourceRepository extends JpaRepository<CloudResource, UUID> {
    List<CloudResource> findByEnvironment_Id(UUID environmentId);
}

