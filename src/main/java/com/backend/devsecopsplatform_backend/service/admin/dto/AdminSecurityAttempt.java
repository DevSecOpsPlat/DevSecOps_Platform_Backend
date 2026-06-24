package com.backend.devsecopsplatform_backend.service.admin.dto;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.LocalDateTime;

public record AdminSecurityAttempt(
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
        LocalDateTime attemptedAt,
        String ipAddress
) {}
