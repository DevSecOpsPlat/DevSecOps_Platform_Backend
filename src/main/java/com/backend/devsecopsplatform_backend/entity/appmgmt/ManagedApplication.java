package com.backend.devsecopsplatform_backend.entity.appmgmt;

import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.entity.User;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Conteneur logique = un namespace Kubernetes. Regroupe les services et les bases
 * de données d'un projet (cf. architecture.md §2.1).
 */
@Entity
@Table(name = "applications", indexes = {
        @Index(name = "idx_app_created_by", columnList = "created_by"),
        @Index(name = "idx_app_slug", columnList = "slug")
}, uniqueConstraints = {
        @UniqueConstraint(name = "uq_app_slug", columnNames = {"slug"})
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ManagedApplication {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "name", nullable = false, length = 200)
    private String name;

    /** Dérivé du nom, unique, sert au nom de namespace (env-<slug>-<shortid>). */
    @Column(name = "slug", nullable = false, length = 120)
    private String slug;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "created_by", nullable = false)
    @JsonIgnoreProperties({"services", "ephemeralEnvironments", "password"})
    private User createdBy;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private Instant updatedAt;

    /** Supprimer le projet supprime aussi ses services (équivalent ON DELETE CASCADE côté JPA). */
    @OneToMany(mappedBy = "managedApplication", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<AppService> services = new ArrayList<>();

    @OneToMany(mappedBy = "application", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<AppDatabase> databases = new ArrayList<>();

    @OneToMany(mappedBy = "application", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<AppDeployment> deployments = new ArrayList<>();
}
