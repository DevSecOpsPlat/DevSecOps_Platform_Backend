package com.backend.devsecopsplatform_backend.controller.application;


import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
public class ApplicationResponse {
    private UUID id;
    private String name;
    private String description;
    private String gitRepositoryUrl;
    private String dockerfilePath;
    private LocalDateTime createdAt;
    private String createdByUsername;

    // ⚠️ Ne JAMAIS retourner le token chiffré au frontend
    private boolean hasGithubToken; // true si un token est configuré
}