package com.backend.devsecopsplatform_backend.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonFormat;
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

@Entity
@Table(name = "ephemeral_environments", indexes = {
        @Index(name = "idx_env_status", columnList = "status"),
        @Index(name = "idx_env_expires", columnList = "expires_at"),
        @Index(name = "idx_env_namespace", columnList = "namespace"),
        @Index(name = "idx_env_requested_by", columnList = "requested_by"),
        @Index(name = "idx_env_application", columnList = "application_id")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class EphemeralEnvironment {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "environment_name", unique = true, nullable = false, length = 100)
    private String environmentName;

    /**
     * Application source de cet environnement
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "application_id", nullable = false)
    @JsonBackReference("app-env") // Enfant de Application
    private Application application;

    @Column(name = "git_branch", nullable = false, length = 255)
    private String gitBranch;


    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "requested_by", nullable = false)
    @JsonIgnoreProperties({"ephemeralEnvironments", "applications", "password"})
    private User requestedBy;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 50)
    private EnvironmentStatus status = EnvironmentStatus.PENDING;


    @Column(name = "namespace", unique = true, length = 100)
    private String namespace;

    @Column(name = "url", length = 500)
    private String url;

    @Column(name = "ttl_hours", nullable = false)
    private Integer ttlHours;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime createdAt;

    @Column(name = "expires_at", nullable = false)
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime expiresAt;

    @Column(name = "destroyed_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime destroyedAt;


    @OneToOne(mappedBy = "environment", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @JsonManagedReference("env-pipeline")
    private PipelineExecution pipelineExecution;

    @OneToMany(mappedBy = "environment", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonManagedReference("env-resource") // Parent de CloudResource
    private List<CloudResource> cloudResources = new ArrayList<>();

    @PrePersist
    public void calculateExpiresAt() {
        if (expiresAt == null && ttlHours != null) {
            expiresAt = LocalDateTime.now().plusHours(ttlHours);
        }
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt) &&
                status != EnvironmentStatus.DESTROYED;
    }

    public boolean isActive() {
        return status == EnvironmentStatus.RUNNING;
    }

    public void extendLifetime(int additionalHours) {
        this.ttlHours += additionalHours;
        this.expiresAt = this.expiresAt.plusHours(additionalHours);
    }

    public void markAsDestroyed() {
        this.status = EnvironmentStatus.DESTROYED;
        // Quand la destruction est déclenchée par le TTL, on veut aligner destroyedAt avec expiresAt.
        // (destroyedAt reste la "date de destruction effective" si expiresAt est absent)
        this.destroyedAt = this.expiresAt != null ? this.expiresAt : LocalDateTime.now();
    }

    public void addPipelineExecution(PipelineExecution execution) {
        this.pipelineExecution = execution;
        execution.setEnvironment(this);
    }

    public void addCloudResource(CloudResource resource) {
        cloudResources.add(resource);
        resource.setEnvironment(this);
    }
}