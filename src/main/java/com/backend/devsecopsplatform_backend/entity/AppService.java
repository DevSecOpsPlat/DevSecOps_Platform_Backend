package com.backend.devsecopsplatform_backend.entity;

import com.backend.devsecopsplatform_backend.configuration.AppCryptoConverter;
import com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ManagedApplication;
import com.backend.devsecopsplatform_backend.entity.appmgmt.ServiceEnvVar;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Service applicatif scannable (repo Git + scan Sonar/DefectDojo) et, optionnellement,
 * déployable dans un {@link ManagedApplication} multi-services.
 */
@Entity
@Table(name = "app_service", indexes = {
        @Index(name = "idx_appsvc_created_by", columnList = "created_by"),
        @Index(name = "idx_appsvc_name", columnList = "name"),
        @Index(name = "idx_appsvc_managed_application", columnList = "managed_application_id")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AppService {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "name", nullable = false, length = 200)
    private String name;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "git_repository_url", nullable = false, length = 500)
    private String gitRepositoryUrl;

    @Column(name = "dockerfile_path", length = 255)
    private String dockerfilePath = "./Dockerfile";

    @Column(name = "encrypted_github_token")
    private String encryptedGithubToken;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "created_by", nullable = false)
    @JsonIgnoreProperties({"services", "ephemeralEnvironments", "password"})
    private User createdBy;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime createdAt;

    @OneToMany(mappedBy = "service", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonManagedReference("app-env")
    private List<EphemeralEnvironment> ephemeralEnvironments = new ArrayList<>();

    // --- Champs multi-services (fusion appmgmt.AppService), tous nullable ---

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "managed_application_id")
    @JsonIgnore
    private ManagedApplication managedApplication;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", length = 20)
    private AppServiceRole role;

    @Convert(converter = AppCryptoConverter.class)
    @Column(name = "git_token", length = 2000)
    private String gitToken;

    @Column(name = "git_branch", length = 200)
    private String gitBranch;

    @Column(name = "build_context", length = 255)
    private String buildContext;

    @Column(name = "exposed_port")
    private Integer exposedPort;

    @Column(name = "depends_on_service_id")
    private UUID dependsOnServiceId;

    @Column(name = "depends_on_database_id")
    private UUID dependsOnDatabaseId;

    @Column(name = "db_url_env_var", length = 120)
    private String dbUrlEnvVar;

    @Column(name = "replicas")
    private Integer replicas;

    @Column(name = "health_check_path", length = 255)
    private String healthCheckPath;

    @Column(name = "cpu_request", length = 20)
    private String cpuRequest;

    @Column(name = "cpu_limit", length = 20)
    private String cpuLimit;

    @Column(name = "memory_request", length = 20)
    private String memoryRequest;

    @Column(name = "memory_limit", length = 20)
    private String memoryLimit;

    @OneToMany(mappedBy = "appService", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<ServiceEnvVar> envVars = new ArrayList<>();

    public void addEphemeralEnvironment(EphemeralEnvironment environment) {
        ephemeralEnvironments.add(environment);
        environment.setService(this);
    }

    public void removeEphemeralEnvironment(EphemeralEnvironment environment) {
        ephemeralEnvironments.remove(environment);
        environment.setService(null);
    }
}
