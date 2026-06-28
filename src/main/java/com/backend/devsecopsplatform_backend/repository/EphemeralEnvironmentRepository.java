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

    long countByRequestedByAndStatus(User user, EnvironmentStatus status);

    Optional<EphemeralEnvironment> findByIdAndRequestedBy(UUID id, User user);

    @Query("SELECT e FROM EphemeralEnvironment e WHERE e.requestedBy = :user ORDER BY e.createdAt DESC")
    List<EphemeralEnvironment> findMyEnvironments(@Param("user") User user);

    List<EphemeralEnvironment> findByStatusNotInAndExpiresAtBefore(Collection<EnvironmentStatus> excludedStatuses,
                                                                   LocalDateTime before);
    List<EphemeralEnvironment> findByApplication_Id(UUID applicationId);

    List<EphemeralEnvironment> findByApplication_IdAndGitBranchOrderByCreatedAtDesc(
            UUID applicationId, String gitBranch);

    Optional<EphemeralEnvironment> findByIdAndApplication_Id(UUID id, UUID applicationId);

    @Query("""
            select distinct e from EphemeralEnvironment e
            left join fetch e.pipelineExecution
            where e.application.id = :applicationId
              and (:branch is null or e.gitBranch = :branch)
            order by e.createdAt desc
            """)
    List<EphemeralEnvironment> findByApplicationWithPipeline(
            @Param("applicationId") UUID applicationId,
            @Param("branch") String branch);

    @Query("""
            select distinct e from EphemeralEnvironment e
            join fetch e.application a
            left join fetch e.pipelineExecution p
            where e.requestedBy = :user
              and a.id = :appId
            order by e.createdAt desc
            """)
    List<EphemeralEnvironment> findByRequestedByAndApplicationIdWithApplicationAndPipelineOrderByCreatedAtDesc(
            @Param("user") User user,
            @Param("appId") UUID appId);

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

    /**
     * Environnements d'un utilisateur avec application et pipeline (évite N+1 pour l'admin).
     */
    @Query("""
            select distinct e from EphemeralEnvironment e
            join fetch e.application a
            left join fetch e.pipelineExecution p
            where e.requestedBy = :user
            order by e.createdAt desc
            """)
    List<EphemeralEnvironment> findByRequestedByWithApplicationAndPipelineOrderByCreatedAtDesc(
            @Param("user") User user);
}