package com.backend.devsecopsplatform_backend.entity;


import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;


@Entity
@Table(name = "security_scans", indexes = {
        @Index(name = "idx_scan_pipeline", columnList = "pipeline_execution_id"),
        @Index(name = "idx_scan_type", columnList = "scan_type"),
        @Index(name = "idx_scan_date", columnList = "scan_date")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SecurityScan {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "pipeline_execution_id", nullable = false)
    @JsonBackReference("pipeline-scan") // Enfant de Pipeline
    private PipelineExecution pipelineExecution;

    @Enumerated(EnumType.STRING)
    @Column(name = "scan_type", nullable = false, length = 50)
    private ScanType scanType;

    @Column(name = "tool_name", nullable = false, length = 100)
    private String toolName;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "vulnerabilities_json", columnDefinition = "jsonb")
    private List<Map<String, Object>> vulnerabilitiesJson;


    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "severity_summary", columnDefinition = "jsonb")
    private Map<String, Integer> severitySummary;

    @CreationTimestamp
    @Column(name = "scan_date", nullable = false, updatable = false)
    private LocalDateTime scanDate;

    // Relation One-to-Many


    @OneToMany(mappedBy = "securityScan", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonManagedReference("scan-recommendation") // Parent de Recommendation
    private List<VulnerabilityRecommendation> recommendations = new ArrayList<>();
    // Méthodes utilitaires

    public int getTotalVulnerabilities() {
        if (vulnerabilitiesJson == null) return 0;
        return vulnerabilitiesJson.size();
    }


    public int getCriticalCount() {
        return severitySummary != null ? severitySummary.getOrDefault("CRITICAL", 0) : 0;
    }


    public int getHighCount() {
        return severitySummary != null ? severitySummary.getOrDefault("HIGH", 0) : 0;
    }

    public boolean hasCriticalOrHighVulnerabilities() {
        return getCriticalCount() > 0 || getHighCount() > 0;
    }

    public void addRecommendation(VulnerabilityRecommendation recommendation) {
        recommendations.add(recommendation);
        recommendation.setSecurityScan(this);
    }
}