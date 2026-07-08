package com.backend.devsecopsplatform_backend.service.qualitygate.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Data;

import java.util.UUID;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecurityGateIngestRequest {

    @JsonProperty("application_id")
    @JsonAlias("applicationId")
    private String applicationIdRaw;

    @JsonProperty("environment_id")
    @JsonAlias("environmentId")
    private String environmentIdRaw;

    @JsonProperty("pipeline_id")
    @JsonAlias({"pipelineId", "gitlab_pipeline_id"})
    private String pipelineId;

    /** {@code scan} ou {@code deploy} (job CI security-validation). */
    private String kind;

    @JsonProperty("deployment_id")
    @JsonAlias("deploymentId")
    private String deploymentIdRaw;

    private String recommendation;
    private Integer critical;
    private Integer high;
    private Integer secrets;
    @JsonProperty("container_critical")
    private Integer containerCritical;
    @JsonProperty("container_high")
    private Integer containerHigh;
    @JsonProperty("sca_medium")
    private Integer scaMedium;
    @JsonProperty("sca_low")
    private Integer scaLow;
    @JsonProperty("semgrep_high")
    private Integer semgrepHigh;
    @JsonProperty("semgrep_medium")
    private Integer semgrepMedium;
    @JsonProperty("semgrep_info")
    private Integer semgrepInfo;
    @JsonProperty("hadolint_errors")
    private Integer hadolintErrors;
    @JsonProperty("checkov_failed")
    private Integer checkovFailed;
    @JsonProperty("dast_high")
    private Integer dastHigh;
    @JsonProperty("dast_medium")
    private Integer dastMedium;
    @JsonProperty("dast_low")
    private Integer dastLow;
    @JsonProperty("sonar_security_rating")
    private String sonarSecurityRating;
    @JsonProperty("sonar_quality_gate")
    private String sonarQualityGate;
    @JsonProperty("sonar_bugs")
    private Integer sonarBugs;
    @JsonProperty("sonar_vulnerabilities")
    private Integer sonarVulnerabilities;
    @JsonProperty("sonar_hotspots")
    private Integer sonarHotspots;
    @JsonProperty("sonar_coverage")
    private String sonarCoverage;
    @JsonProperty("sonar_blockers")
    private Integer sonarBlockers;
    @JsonProperty("sonar_criticals")
    private Integer sonarCriticals;
    @JsonProperty("sonar_ncloc")
    private Integer sonarNcloc;
    private JsonNode summary;
    @JsonProperty("quality_gate")
    private JsonNode qualityGate;

    @JsonIgnore
    public UUID getApplicationId() {
        return parseUuid(applicationIdRaw);
    }

    @JsonIgnore
    public UUID getEnvironmentId() {
        return parseUuid(environmentIdRaw);
    }

    @JsonIgnore
    public UUID getDeploymentId() {
        return parseUuid(deploymentIdRaw);
    }

    public boolean isDeployKind() {
        return kind != null && kind.equalsIgnoreCase("deploy");
    }

    private static UUID parseUuid(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(raw.trim());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
