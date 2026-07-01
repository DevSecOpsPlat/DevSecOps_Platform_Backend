package com.backend.devsecopsplatform_backend.entity.appmgmt;

import com.backend.devsecopsplatform_backend.configuration.AppCryptoConverter;
import com.fasterxml.jackson.annotation.JsonIgnore;
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
 * Service applicatif déployable depuis un repo Git (front / back / worker),
 * cf. architecture.md §2.2.
 *
 * <p>Les dépendances ({@code depends_on_service_id}, {@code depends_on_database_id})
 * sont stockées en colonnes UUID simples : la profondeur est bornée (service → backend
 * → BD), pas besoin de graphe générique (cf. §3.3).</p>
 */
@Entity
@Table(name = "app_service", indexes = {
        @Index(name = "idx_appsvc_application", columnList = "application_id")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AppService {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "application_id", nullable = false)
    @JsonIgnore
    private ManagedApplication application;

    @Column(name = "name", nullable = false, length = 120)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false, length = 20)
    private AppServiceRole role;

    @Column(name = "git_repository_url", nullable = false, length = 500)
    private String gitRepositoryUrl;

    /** Token Git chiffré au repos (AES-256-GCM), masqué dans l'API. */
    @Convert(converter = AppCryptoConverter.class)
    @Column(name = "git_token", length = 2000)
    private String gitToken;

    @Column(name = "git_branch", nullable = false, length = 200)
    private String gitBranch = "main";

    @Column(name = "dockerfile_path", nullable = false, length = 255)
    private String dockerfilePath = "Dockerfile";

    @Column(name = "build_context", nullable = false, length = 255)
    private String buildContext = ".";

    @Column(name = "exposed_port", nullable = false)
    private Integer exposedPort;

    @Column(name = "depends_on_service_id")
    private UUID dependsOnServiceId;

    @Column(name = "depends_on_database_id")
    private UUID dependsOnDatabaseId;

    /** Nom de la variable où injecter l'URL BD (utile seulement si dépendance BD). */
    @Column(name = "db_url_env_var", length = 120)
    private String dbUrlEnvVar = "DATABASE_URL";

    @Column(name = "replicas", nullable = false)
    private Integer replicas = 1;

    @Column(name = "health_check_path", length = 255)
    private String healthCheckPath;

    // Limites de ressources (optionnelles, défauts raisonnables) — cf. §7.8
    @Column(name = "cpu_request", length = 20)
    private String cpuRequest = "100m";

    @Column(name = "cpu_limit", length = 20)
    private String cpuLimit = "500m";

    @Column(name = "memory_request", length = 20)
    private String memoryRequest = "128Mi";

    @Column(name = "memory_limit", length = 20)
    private String memoryLimit = "512Mi";

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private Instant updatedAt;

    @OneToMany(mappedBy = "appService", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ServiceEnvVar> envVars = new ArrayList<>();
}
