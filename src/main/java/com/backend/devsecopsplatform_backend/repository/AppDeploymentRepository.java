package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeployment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AppDeploymentRepository extends JpaRepository<AppDeployment, UUID> {

    List<AppDeployment> findByApplication_IdOrderByCreatedAtDesc(UUID applicationId);

    Optional<AppDeployment> findByIdAndApplication_Id(UUID id, UUID applicationId);
}
