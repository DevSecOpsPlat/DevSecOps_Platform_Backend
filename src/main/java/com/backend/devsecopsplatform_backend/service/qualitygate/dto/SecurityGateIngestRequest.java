package com.backend.devsecopsplatform_backend.service.qualitygate.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Data;

import java.util.UUID;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecurityGateIngestRequest {
    @JsonProperty("environment_id")
    private UUID environmentId;
    private String pipelineId;
    private String recommendation;
    private Integer critical;
    private Integer high;
    private Integer secrets;
    @JsonProperty("container_critical")
    private Integer containerCritical;
    @JsonProperty("dast_high")
    private Integer dastHigh;
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
}
