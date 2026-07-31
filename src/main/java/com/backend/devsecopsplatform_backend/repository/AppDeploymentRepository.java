package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeployment;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AppDeploymentRepository extends JpaRepository<AppDeployment, UUID> {

    List<AppDeployment> findByApplication_IdOrderByCreatedAtDesc(UUID applicationId);

    Optional<AppDeployment> findByIdAndApplication_Id(UUID id, UUID applicationId);

    Optional<AppDeployment> findByEphemeralEnvironmentId(UUID ephemeralEnvironmentId);

    /** Charge {@code application} uniquement — pas les collections (évite le conflit bag Hibernate). */
    @EntityGraph(attributePaths = {"application"})
    Optional<AppDeployment> findWithApplicationById(UUID id);

    @EntityGraph(attributePaths = {"application", "application.createdBy"})
    List<AppDeployment> findByStatus(com.backend.devsecopsplatform_backend.entity.appmgmt.AppDeploymentStatus status);
}
