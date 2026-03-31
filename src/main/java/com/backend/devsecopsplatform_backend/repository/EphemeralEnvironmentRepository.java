package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.EphemeralEnvironment;
import com.backend.devsecopsplatform_backend.entity.EnvironmentStatus;
import com.backend.devsecopsplatform_backend.entity.User;
import org.springframework.data.domain.Pageable;  // ← Importer le bon Pageable
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface EphemeralEnvironmentRepository extends JpaRepository<EphemeralEnvironment, UUID> {

    List<EphemeralEnvironment> findByRequestedByOrderByCreatedAtDesc(User user);

    List<EphemeralEnvironment> findByRequestedByAndStatus(User user, EnvironmentStatus status);

    Optional<EphemeralEnvironment> findByIdAndRequestedBy(UUID id, User user);

    @Query("SELECT e FROM EphemeralEnvironment e WHERE e.requestedBy = :user ORDER BY e.createdAt DESC")
    List<EphemeralEnvironment> findMyEnvironments(@Param("user") User user);

    List<EphemeralEnvironment> findByStatusNotInAndExpiresAtBefore(Collection<EnvironmentStatus> excludedStatuses,
                                                                   LocalDateTime before);
    List<EphemeralEnvironment> findByApplication_Id(UUID applicationId);

    // ✅ Correction: Utiliser Pageable de Spring, pas java.awt.print.Pageable
    @Query("SELECT e FROM EphemeralEnvironment e " +
            "WHERE e.requestedBy = :user " +
            "ORDER BY e.createdAt DESC")
    List<EphemeralEnvironment> findByUserOrderByCreatedAtDesc(@Param("user") User user, Pageable pageable);

    default EphemeralEnvironment findFirstByUserOrderByCreatedAtDesc(User user) {
        List<EphemeralEnvironment> results = findByUserOrderByCreatedAtDesc(user, PageRequest.of(0, 1));
        return results.isEmpty() ? null : results.get(0);
    }

    /** Pour fetch fichier source (join fetch application → gitRepositoryUrl + token). */
    @Query("select distinct e from EphemeralEnvironment e join fetch e.application where e.id = :id")
    Optional<EphemeralEnvironment> findByIdWithApplication(@Param("id") UUID id);
}