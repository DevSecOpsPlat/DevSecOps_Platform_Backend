package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository pour l'entité {@link AppService} (table {@code app_service}).
 */
@Repository
public interface AppServiceRepository extends JpaRepository<AppService, UUID> {

    List<AppService> findByCreatedBy(User user);

    List<AppService> findByName(String name);

    Optional<AppService> findByNameIgnoreCase(String name);

    List<AppService> findByGitRepositoryUrl(String gitRepositoryUrl);

    Optional<AppService> findByCreatedByAndGitRepositoryUrl(User user, String gitRepositoryUrl);

    boolean existsByName(String name);

    boolean existsByGitRepositoryUrl(String gitRepositoryUrl);

    List<AppService> findByCreatedByAndNameContainingIgnoreCase(User user, String nameContains);

    long countByCreatedBy(User user);

    List<AppService> findByCreatedByOrderByCreatedAtDesc(User user);

    @Query("SELECT a FROM AppService a WHERE a.encryptedGithubToken IS NOT NULL")
    List<AppService> findAllWithGithubToken();

    @Query("SELECT a FROM AppService a WHERE a.createdBy = :user AND a.encryptedGithubToken IS NOT NULL")
    List<AppService> findByCreatedByWithGithubToken(@Param("user") User user);

    Optional<AppService> findByIdAndCreatedBy(UUID id, User user);

    @Query("SELECT a FROM AppService a WHERE LOWER(a.name) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR LOWER(a.description) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    List<AppService> searchApplications(@Param("searchTerm") String searchTerm);

    @Query("SELECT a FROM AppService a WHERE a.createdBy = :user AND (LOWER(a.name) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR LOWER(a.description) LIKE LOWER(CONCAT('%', :searchTerm, '%')))")
    List<AppService> searchUserApplications(@Param("user") User user, @Param("searchTerm") String searchTerm);

    @Query("SELECT a FROM AppService a ORDER BY a.createdAt DESC LIMIT :limit")
    List<AppService> findLatestApplications(@Param("limit") int limit);

    @Query("SELECT a FROM AppService a LEFT JOIN a.ephemeralEnvironments e GROUP BY a.id ORDER BY COUNT(e) DESC LIMIT :limit")
    List<AppService> findMostUsedApplications(@Param("limit") int limit);

    void deleteByCreatedBy(User user);

    @Query("SELECT a FROM AppService a WHERE a.createdAt BETWEEN :startDate AND :endDate")
    List<AppService> findApplicationsCreatedBetween(
            @Param("startDate") java.time.LocalDateTime startDate,
            @Param("endDate") java.time.LocalDateTime endDate
    );

    @Query("SELECT a.createdBy.username, COUNT(a) FROM AppService a GROUP BY a.createdBy.username")
    List<Object[]> countApplicationsByUser();

    @Query("SELECT a FROM AppService a WHERE SIZE(a.ephemeralEnvironments) = 0")
    List<AppService> findUnusedApplications();

    @Query("SELECT DISTINCT a FROM AppService a JOIN a.ephemeralEnvironments e WHERE e.status = 'RUNNING'")
    List<AppService> findActiveApplications();

    List<AppService> findByManagedApplication_Id(UUID managedApplicationId);

    Optional<AppService> findByIdAndManagedApplication_Id(UUID id, UUID managedApplicationId);

    long countByDependsOnDatabaseId(UUID databaseId);

    long countByDependsOnServiceId(UUID serviceId);
}
