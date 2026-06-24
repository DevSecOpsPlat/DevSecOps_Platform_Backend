package com.backend.devsecopsplatform_backend.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "finding_occurrences", indexes = {
        @Index(name = "idx_occ_finding", columnList = "finding_id"),
        @Index(name = "idx_occ_pipeline", columnList = "pipeline_execution_id"),
        @Index(name = "idx_occ_tool", columnList = "tool_name")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class FindingOccurrence {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "finding_id", nullable = false)
    @JsonBackReference("finding-occurrence")
    private Finding finding;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "pipeline_execution_id")
    private PipelineExecution pipelineExecution;

    /**
     * Optionnel: rattacher une occurrence à un scan "brut" (ancien modèle).
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "security_scan_id")
    private SecurityScan securityScan;

    @Column(name = "tool_name", nullable = false, length = 100)
    private String toolName;

    @Column(name = "job_name", length = 255)
    private String jobName;

    @Column(name = "artifact_path", length = 1000)
    private String artifactPath;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "evidence_json", columnDefinition = "jsonb")
    private Map<String, Object> evidenceJson;

    @CreationTimestamp
    @Column(name = "observed_at", nullable = false, updatable = false)
    private LocalDateTime observedAt;
}

