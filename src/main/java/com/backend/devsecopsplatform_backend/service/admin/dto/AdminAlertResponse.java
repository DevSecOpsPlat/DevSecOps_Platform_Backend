package com.backend.devsecopsplatform_backend.service.admin.dto;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.LocalDateTime;
import java.util.UUID;

public record AdminAlertResponse(
        UUID id,
        String type,
        String message,
        String status,
        UUID relatedUserId,
        String relatedUsername,
        String ipAddress,
        String detailsJson,
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
        LocalDateTime createdAt
) {}
