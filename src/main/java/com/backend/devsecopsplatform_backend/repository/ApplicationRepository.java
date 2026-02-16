package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.Application;
import com.backend.devsecopsplatform_backend.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository pour l'entité Application
 * Gère l'accès aux données des applications dans la base de données
 */
@Repository
public interface ApplicationRepository extends JpaRepository<Application, UUID> {

    /**
     * Trouve toutes les applications créées par un utilisateur
     *
     * @param user Utilisateur créateur
     * @return Liste des applications
     */
    List<Application> findByCreatedBy(User user);

    /**
     * Trouve une application par son nom (exact)
     *
     * @param name Nom de l'application
     * @return Liste des applications avec ce nom
     */
    List<Application> findByName(String name);

    /**
     * Trouve une application par son nom (insensible à la casse)
     *
     * @param name Nom de l'application
     * @return Optional contenant l'application si trouvée
     */
    Optional<Application> findByNameIgnoreCase(String name);

    /**
     * Trouve les applications par URL de repository Git
     * Utile pour éviter les doublons de repositories
     *
     * @param gitRepositoryUrl URL du repository Git
     * @return Liste des applications avec cette URL
     */
    List<Application> findByGitRepositoryUrl(String gitRepositoryUrl);

    /**
     * Trouve une application par créateur et URL du repository (pour déploiement)
     */
    Optional<Application> findByCreatedByAndGitRepositoryUrl(User user, String gitRepositoryUrl);

    /**
     * Vérifie si une application existe avec un nom donné
     *
     * @param name Nom de l'application
     * @return true si elle existe, false sinon
     */
    boolean existsByName(String name);

    /**
     * Vérifie si une application existe avec une URL de repository donnée
     *
     * @param gitRepositoryUrl URL du repository
     * @return true si elle existe, false sinon
     */
    boolean existsByGitRepositoryUrl(String gitRepositoryUrl);

    /**
     * Trouve toutes les applications créées par un utilisateur avec un nom contenant
     *
     * @param user Utilisateur créateur
     * @param nameContains Partie du nom à chercher
     * @return Liste des applications
     */
    List<Application> findByCreatedByAndNameContainingIgnoreCase(User user, String nameContains);

    /**
     * Compte le nombre d'applications créées par un utilisateur
     *
     * @param user Utilisateur créateur
     * @return Nombre d'applications
     */
    long countByCreatedBy(User user);

    /**
     * Trouve les applications créées par un utilisateur, triées par date de création (descendant)
     *
     * @param user Utilisateur créateur
     * @return Liste des applications triées
     */
    List<Application> findByCreatedByOrderByCreatedAtDesc(User user);

    /**
     * Trouve les applications qui ont un token GitHub configuré
     *
     * @return Liste des applications avec token
     */
    @Query("SELECT a FROM Application a WHERE a.encryptedGithubToken IS NOT NULL")
    List<Application> findAllWithGithubToken();

    /**
     * Trouve les applications d'un utilisateur qui ont un token GitHub
     *
     * @param user Utilisateur créateur
     * @return Liste des applications avec token
     */
    @Query("SELECT a FROM Application a WHERE a.createdBy = :user AND a.encryptedGithubToken IS NOT NULL")
    List<Application> findByCreatedByWithGithubToken(@Param("user") User user);

    /**
     * Trouve une application par son ID et son créateur
     * Utile pour vérifier que l'utilisateur est bien le propriétaire
     *
     * @param id ID de l'application
     * @param user Utilisateur créateur
     * @return Optional contenant l'application si trouvée
     */
    Optional<Application> findByIdAndCreatedBy(UUID id, User user);

    /**
     * Recherche des applications par nom (recherche partielle, insensible à la casse)
     *
     * @param searchTerm Terme de recherche
     * @return Liste des applications correspondantes
     */
    @Query("SELECT a FROM Application a WHERE LOWER(a.name) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR LOWER(a.description) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    List<Application> searchApplications(@Param("searchTerm") String searchTerm);

    /**
     * Recherche des applications d'un utilisateur par nom ou description
     *
     * @param user Utilisateur créateur
     * @param searchTerm Terme de recherche
     * @return Liste des applications correspondantes
     */
    @Query("SELECT a FROM Application a WHERE a.createdBy = :user AND (LOWER(a.name) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR LOWER(a.description) LIKE LOWER(CONCAT('%', :searchTerm, '%')))")
    List<Application> searchUserApplications(@Param("user") User user, @Param("searchTerm") String searchTerm);

    /**
     * Trouve les N dernières applications créées
     *
     * @param limit Nombre d'applications à retourner
     * @return Liste des dernières applications
     */
    @Query("SELECT a FROM Application a ORDER BY a.createdAt DESC LIMIT :limit")
    List<Application> findLatestApplications(@Param("limit") int limit);

    /**
     * Trouve les applications avec le plus d'environnements éphémères
     *
     * @param limit Nombre d'applications à retourner
     * @return Liste des applications les plus utilisées
     */
    @Query("SELECT a FROM Application a LEFT JOIN a.ephemeralEnvironments e GROUP BY a.id ORDER BY COUNT(e) DESC LIMIT :limit")
    List<Application> findMostUsedApplications(@Param("limit") int limit);

    /**
     * Supprime toutes les applications d'un utilisateur
     * ⚠️ À utiliser avec précaution (cascade sur les environnements éphémères)
     *
     * @param user Utilisateur créateur
     */
    void deleteByCreatedBy(User user);

    /**
     * Trouve les applications créées entre deux dates
     *
     * @param startDate Date de début
     * @param endDate Date de fin
     * @return Liste des applications
     */
    @Query("SELECT a FROM Application a WHERE a.createdAt BETWEEN :startDate AND :endDate")
    List<Application> findApplicationsCreatedBetween(
            @Param("startDate") java.time.LocalDateTime startDate,
            @Param("endDate") java.time.LocalDateTime endDate
    );

    /**
     * Compte les applications par utilisateur
     *
     * @return Map avec le nombre d'applications par utilisateur
     */
    @Query("SELECT a.createdBy.username, COUNT(a) FROM Application a GROUP BY a.createdBy.username")
    List<Object[]> countApplicationsByUser();

    /**
     * Trouve les applications sans environnements éphémères (jamais utilisées)
     *
     * @return Liste des applications non utilisées
     */
    @Query("SELECT a FROM Application a WHERE SIZE(a.ephemeralEnvironments) = 0")
    List<Application> findUnusedApplications();

    /**
     * Trouve les applications actives (avec au moins un environnement RUNNING)
     *
     * @return Liste des applications actives
     */
    @Query("SELECT DISTINCT a FROM Application a JOIN a.ephemeralEnvironments e WHERE e.status = 'RUNNING'")
    List<Application> findActiveApplications();
}