package com.backend.devsecopsplatform_backend.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Snapshot complet du dashboard Quality Gate (source backend : Sonar + DefectDojo + stages GitLab).
 * Indépendant du rapport CI security-validation.
 */
@Entity
@Table(name = "quality_gate_snapshots", indexes = {
        @Index(name = "idx_qg_snap_env_created", columnList = "environment_id, created_at"),
        @Index(name = "idx_qg_snap_app_branch_created", columnList = "application_id, branch, created_at")
}, uniqueConstraints = {
        @UniqueConstraint(name = "uk_qg_snap_pipeline_exec", columnNames = "pipeline_execution_id")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class QualityGateSnapshot {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "application_id", nullable = false)
    private UUID applicationId;

    @Column(name = "environment_id", nullable = false)
    private UUID environmentId;

    @Column(name = "pipeline_execution_id", nullable = false, unique = true)
    private UUID pipelineExecutionId;

    @Column(name = "branch", nullable = false, length = 255)
    private String branch;

    @Column(name = "gitlab_pipeline_id")
    private Long gitlabPipelineId;

    /** PIPELINE_SYNC | CI_INGEST | MANUAL */
    @Column(name = "source", nullable = false, length = 32)
    private String source;

    @Column(name = "evaluated_at")
    private Instant evaluatedAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "payload", nullable = false, columnDefinition = "jsonb")
    private Map<String, Object> payload;

    /** ncloc SonarQube au moment du snapshot (denormalisé pour affichage / requêtes). */
    @Column(name = "ncloc")
    private Integer ncloc;
}
