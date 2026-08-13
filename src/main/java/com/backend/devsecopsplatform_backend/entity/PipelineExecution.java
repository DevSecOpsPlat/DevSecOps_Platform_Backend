package com.backend.devsecopsplatform_backend.entity;

import com.backend.devsecopsplatform_backend.entity.appmgmt.ScanBatch;
import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;
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
        @Index(name = "idx_pipeline_app", columnList = "app_service_id"),
        @Index(name = "idx_pipeline_gitlab", columnList = "gitlab_pipeline_id"),
        @Index(name = "idx_pipeline_status", columnList = "status"),
        @Index(name = "idx_pipeline_scan_batch", columnList = "scan_batch_id")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PipelineExecution {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @OneToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "environment_id", nullable = true, unique = true)
    @JsonBackReference("env-pipeline")
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private EphemeralEnvironment environment;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "app_service_id", nullable = false)
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private AppService appService;

    /**
     * Lot de scan application (nullable = historique pré-lot / exécutions hors batch).
     * UNIQUE (gitlab_pipeline_id, app_service_id) posée en SQL si données propres —
     * pas via Hibernate ddl-auto (évite plantage au démarrage).
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "scan_batch_id")
    @JsonBackReference("batch-executions")
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private ScanBatch scanBatch;

    @Enumerated(EnumType.STRING)
    @Column(name = "execution_kind", nullable = false, length = 30)
    private PipelineExecutionKind executionKind = PipelineExecutionKind.SCAN;

    @Column(name = "git_branch", nullable = false, length = 255)
    private String gitBranch = "main";

    /** SHA HEAD résolu au déclenchement (branche) — D2 / D6. */
    @Column(name = "commit_sha", length = 64)
    private String commitSha;

    /**
     * Dernier HEAD connu (cache posture) — rafraîchi au plus toutes les
     * {@code scan.posture.head-check-ttl-ms} minutes côté {@code securityPosture}.
     */
    @Column(name = "checked_head_sha", length = 64)
    private String checkedHeadSha;

    @Column(name = "head_checked_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime headCheckedAt;

    @Column(name = "gitlab_pipeline_id")
    private Long gitlabPipelineId;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 50)
    private PipelineStatus status = PipelineStatus.PENDING;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "stages_json", columnDefinition = "jsonb")
    private Map<String, Object> stagesJson;

    /** Verdict CI security-validation + métriques summary.json (quality-gate.json). */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "quality_gate_json", columnDefinition = "jsonb")
    private Map<String, Object> qualityGateJson;

    @Column(name = "started_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime startedAt;

    @Column(name = "finished_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime finishedAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime createdAt;


    @OneToMany(mappedBy = "pipelineExecution", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonManagedReference("pipeline-scan")
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
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
