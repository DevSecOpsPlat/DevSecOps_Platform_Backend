package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.appmgmt.AppService;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AppServiceRepository extends JpaRepository<AppService, UUID> {

    List<AppService> findByApplication_Id(UUID applicationId);

    Optional<AppService> findByIdAndApplication_Id(UUID id, UUID applicationId);

    long countByDependsOnDatabaseId(UUID databaseId);

    long countByDependsOnServiceId(UUID serviceId);
}
