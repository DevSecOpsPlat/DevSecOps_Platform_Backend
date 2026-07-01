package com.backend.devsecopsplatform_backend.service.qualitygate;

import java.util.UUID;

/** Émis après ingestion des artifacts aggregate-report (summary + findings persistés). */
public record PipelineArtifactsIngestedEvent(UUID pipelineExecutionId, Long gitlabPipelineId) {}
