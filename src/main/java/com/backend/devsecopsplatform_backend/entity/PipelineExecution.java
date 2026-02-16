package com.backend.devsecopsplatform_backend.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Entité représentant une exécution de pipeline GitLab CI/CD
 */
@Entity
@Table(name = "pipeline_executions", indexes = {
        @Index(name = "idx_pipeline_env", columnList = "environment_id"),
        @Index(name = "idx_pipeline_gitlab", columnList = "gitlab_pipeline_id"),
        @Index(name = "idx_pipeline_status", columnList = "status")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PipelineExecution {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "environment_id", nullable = false)
    @JsonBackReference("env-pipeline") // Enfant de Environment
    private EphemeralEnvironment environment;

    @Column(name = "gitlab_pipeline_id")
    private Integer gitlabPipelineId;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 50)
    private PipelineStatus status = PipelineStatus.PENDING;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "stages_json", columnDefinition = "jsonb")
    private Map<String, Object> stagesJson;

    @Column(name = "started_at")
    private LocalDateTime startedAt;

    @Column(name = "finished_at")
    private LocalDateTime finishedAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;


    @OneToMany(mappedBy = "pipelineExecution", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonManagedReference("pipeline-scan") // Parent de Scan
    private List<SecurityScan> securityScans = new ArrayList<>();
    public boolean isFinished() {
        return status == PipelineStatus.SUCCESS ||
                status == PipelineStatus.FAILED ||
                status == PipelineStatus.CANCELED;
    }

    public boolean isRunning() {
        return status == PipelineStatus.RUNNING;
    }


    public Long getDurationInSeconds() {
        if (startedAt != null && finishedAt != null) {
            return java.time.Duration.between(startedAt, finishedAt).getSeconds();
        }
        return null;
    }

    public void markAsStarted() {
        this.status = PipelineStatus.RUNNING;
        this.startedAt = LocalDateTime.now();
    }

    public void markAsSuccess() {
        this.status = PipelineStatus.SUCCESS;
        this.finishedAt = LocalDateTime.now();
    }

    public void markAsFailed() {
        this.status = PipelineStatus.FAILED;
        this.finishedAt = LocalDateTime.now();
    }

    public void addSecurityScan(SecurityScan scan) {
        securityScans.add(scan);
        scan.setPipelineExecution(this);
    }
}