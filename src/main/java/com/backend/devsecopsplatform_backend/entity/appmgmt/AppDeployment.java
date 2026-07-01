package com.backend.devsecopsplatform_backend.entity.appmgmt;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Exécution de déploiement d'une application managée (produit le namespace + les
 * workloads), cf. architecture.md §2.5. Le scan (pipeline existant) peut se rattacher
 * à ce déploiement puisqu'il scanne un environnement qui tourne.
 */
@Entity
@Table(name = "app_deployment", indexes = {
        @Index(name = "idx_appdeploy_application", columnList = "application_id"),
        @Index(name = "idx_appdeploy_namespace", columnList = "namespace")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AppDeployment {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "application_id", nullable = false)
    @JsonIgnore
    private ManagedApplication application;

    @Column(name = "namespace", nullable = false, length = 200)
    private String namespace;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private AppDeploymentStatus status = AppDeploymentStatus.PENDING;

    @Column(name = "gitlab_pipeline_id")
    private Long gitlabPipelineId;

    @Column(name = "deployed_at")
    private Instant deployedAt;

    /** État par service (Ready / NotReady / URL interne). */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "services_state", columnDefinition = "jsonb")
    private Map<String, Object> servicesState = new HashMap<>();

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private Instant updatedAt;
}
