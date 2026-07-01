package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.appmgmt.AppDatabase;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AppDatabaseRepository extends JpaRepository<AppDatabase, UUID> {

    List<AppDatabase> findByApplication_Id(UUID applicationId);

    Optional<AppDatabase> findByIdAndApplication_Id(UUID id, UUID applicationId);
}
