package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.appmgmt.ServiceEnvVar;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ServiceEnvVarRepository extends JpaRepository<ServiceEnvVar, UUID> {

    List<ServiceEnvVar> findByAppService_Id(UUID appServiceId);

    Optional<ServiceEnvVar> findByIdAndAppService_Id(UUID id, UUID appServiceId);
}
