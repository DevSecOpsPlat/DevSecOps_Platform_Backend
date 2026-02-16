package com.backend.devsecopsplatform_backend.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "cloud_resources", indexes = {
        @Index(name = "idx_resource_env", columnList = "environment_id"),
        @Index(name = "idx_resource_type", columnList = "resource_type"),
        @Index(name = "idx_resource_name", columnList = "resource_name")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CloudResource {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;


    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "environment_id", nullable = false)
    @JsonBackReference("env-resource")
    private EphemeralEnvironment environment;

    @Enumerated(EnumType.STRING)
    @Column(name = "resource_type", nullable = false, length = 100)
    private ResourceType resourceType;


    @Column(name = "resource_name", nullable = false, length = 255)
    private String resourceName;


    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "resource_metadata", columnDefinition = "jsonb")
    private Map<String, Object> resourceMetadata;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;


    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;


    public boolean isKubernetesResource() {
        return resourceType == ResourceType.POD ||
                resourceType == ResourceType.SERVICE ||
                resourceType == ResourceType.DEPLOYMENT ||
                resourceType == ResourceType.PVC ||
                resourceType == ResourceType.INGRESS ||
                resourceType == ResourceType.SECRET ||
                resourceType == ResourceType.CONFIGMAP;
    }


    public boolean isDatabase() {
        return resourceType == ResourceType.DATABASE;
    }

    public void markAsDeleted() {
        this.deletedAt = LocalDateTime.now();
    }

    public boolean isDeleted() {
        return deletedAt != null;
    }

    public Double getEstimatedCost() {
        if (resourceMetadata != null && resourceMetadata.containsKey("cost")) {
            Object cost = resourceMetadata.get("cost");
            if (cost instanceof Number) {
                return ((Number) cost).doubleValue();
            }
        }
        return 0.0;
    }
}