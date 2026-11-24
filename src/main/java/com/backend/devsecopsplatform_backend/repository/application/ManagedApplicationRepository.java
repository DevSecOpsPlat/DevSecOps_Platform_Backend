package com.backend.devsecopsplatform_backend.repository.application;

import com.backend.devsecopsplatform_backend.entity.user.User;
import com.backend.devsecopsplatform_backend.entity.application.ManagedApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ManagedApplicationRepository extends JpaRepository<ManagedApplication, UUID> {

    List<ManagedApplication> findByCreatedByOrderByCreatedAtDesc(User user);

    Optional<ManagedApplication> findByIdAndCreatedBy(UUID id, User user);

    boolean existsBySlug(String slug);
}
