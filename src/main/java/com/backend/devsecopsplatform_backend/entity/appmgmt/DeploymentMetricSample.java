package com.backend.devsecopsplatform_backend.entity.appmgmt;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * Échantillon de métriques namespace (CPU/MEM/net/disk) pour historique long terme.
 */
@Entity
@Table(name = "deployment_metric_sample", indexes = {
        @Index(name = "idx_metric_deployment_sampled", columnList = "deployment_id,sampled_at"),
        @Index(name = "idx_metric_app_sampled", columnList = "application_id,sampled_at")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class DeploymentMetricSample {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "deployment_id", nullable = false)
    private UUID deploymentId;

    @Column(name = "application_id", nullable = false)
    private UUID applicationId;

    @Column(name = "namespace", length = 200)
    private String namespace;

    @Column(name = "sampled_at", nullable = false)
    private Instant sampledAt;

    @Column(name = "cpu_millicores")
    private Double cpuMillicores;

    @Column(name = "memory_bytes")
    private Long memoryBytes;

    @Column(name = "network_rx_bytes")
    private Long networkRxBytes;

    @Column(name = "network_tx_bytes")
    private Long networkTxBytes;

    @Column(name = "fs_used_bytes")
    private Long fsUsedBytes;

    @Column(name = "ready_pods")
    private Integer readyPods;

    @Column(name = "total_pods")
    private Integer totalPods;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}
