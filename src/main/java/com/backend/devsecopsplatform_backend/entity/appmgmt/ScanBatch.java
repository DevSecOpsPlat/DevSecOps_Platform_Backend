package com.backend.devsecopsplatform_backend.entity.appmgmt;

import com.backend.devsecopsplatform_backend.entity.PipelineExecution;
import com.backend.devsecopsplatform_backend.entity.User;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
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
 * Lot de scan au niveau {@link ManagedApplication}.
 * Un seul {@code gitlabPipelineId} (D1) ; N {@link PipelineExecution} SCAN rattachées.
 * Verdict application figé dans {@code verdict} / {@code securityScore} / {@code grade} / payload (D6).
 */
@Entity
@Table(name = "scan_batches", indexes = {
        @Index(name = "idx_scan_batch_app", columnList = "managed_application_id"),
        @Index(name = "idx_scan_batch_gitlab", columnList = "gitlab_pipeline_id"),
        @Index(name = "idx_scan_batch_status", columnList = "status"),
        @Index(name = "idx_scan_batch_created", columnList = "created_at")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ScanBatch {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "managed_application_id", nullable = false)
    @JsonIgnoreProperties({"services", "databases", "deployments", "createdBy"})
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private ManagedApplication managedApplication;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30)
    private ScanBatchStatus status = ScanBatchStatus.PENDING;

    /** Pipeline GitLab unique du lot (même id pour toutes les exécutions service). */
    @Column(name = "gitlab_pipeline_id")
    private Long gitlabPipelineId;

    /**
     * Nombre de services prévus figé à la création du lot (Chantier 2).
     * Ne pas dériver de {@code executions.size()} — sinon PARTIAL/COMPLETE ment.
     */
    @Column(name = "expected_service_count", nullable = false)
    private int expectedServiceCount;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "triggered_by", nullable = false)
    @JsonIgnoreProperties({"services", "ephemeralEnvironments", "password"})
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private User triggeredBy;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "finished_at")
    private LocalDateTime finishedAt;

    /** Verdict officiel application (ex. RECOMMENDED / NOT_RECOMMENDED / INDETERMINE) — figé à la fin. */
    @Column(name = "verdict", length = 40)
    private String verdict;

    /** Score posture application ; null si hard gate violé (D5). */
    @Column(name = "security_score")
    private Integer securityScore;

    @Column(name = "grade", length = 2)
    private String grade;

    /**
     * Contributions par service, gates violés, fraîcheur, exhaustivité.
     * Structure peuplée au Chantier 4 ; opaque au Chantier 1.
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "verdict_payload_json", columnDefinition = "jsonb")
    private Map<String, Object> verdictPayloadJson;

    @OneToMany(mappedBy = "scanBatch", fetch = FetchType.LAZY)
    @OrderBy("createdAt ASC")
    @JsonManagedReference("batch-executions")
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private List<PipelineExecution> executions = new ArrayList<>();
}
