package com.backend.devsecopsplatform_backend.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "findings", indexes = {
        @Index(name = "idx_finding_tool", columnList = "tool_name"),
        @Index(name = "idx_finding_type", columnList = "scan_type"),
        @Index(name = "idx_finding_severity", columnList = "severity"),
        @Index(name = "idx_finding_status", columnList = "status")
}, uniqueConstraints = {
        @UniqueConstraint(name = "uq_finding_fingerprint", columnNames = {"fingerprint"})
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    /**
     * Empreinte stable pour dédupliquer à travers runs/pipelines.
     */
    @Column(name = "fingerprint", nullable = false, length = 128)
    private String fingerprint;

    @Enumerated(EnumType.STRING)
    @Column(name = "scan_type", nullable = false, length = 50)
    private ScanType scanType;

    @Column(name = "tool_name", nullable = false, length = 100)
    private String toolName;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", length = 20)
    private Severity severity;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30)
    private FindingStatus status = FindingStatus.OPEN;

    @Column(name = "rule_id", length = 255)
    private String ruleId;

    @Column(name = "title", length = 500)
    private String title;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "file_path", length = 1000)
    private String filePath;

    @Column(name = "line_start")
    private Integer lineStart;

    @Column(name = "line_end")
    private Integer lineEnd;

    @Column(name = "cve", length = 100)
    private String cve;

    @Column(name = "cwe", length = 100)
    private String cwe;

    @Column(name = "package_name", length = 255)
    private String packageName;

    @Column(name = "installed_version", length = 255)
    private String installedVersion;

    @Column(name = "fixed_version", length = 255)
    private String fixedVersion;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}

