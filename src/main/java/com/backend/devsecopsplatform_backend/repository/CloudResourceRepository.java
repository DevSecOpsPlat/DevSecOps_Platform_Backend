package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.CloudResource;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface CloudResourceRepository extends JpaRepository<CloudResource, UUID> {
    List<CloudResource> findByEnvironment_Id(UUID environmentId);
}

