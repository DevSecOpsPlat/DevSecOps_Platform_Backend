package com.backend.devsecopsplatform_backend.service.admin.dto;

import java.util.List;
import java.util.UUID;

public record AdminSecurityAlert(
        UUID userId,
        String username,
        String email,
        int failedCount,
        List<AdminSecurityAttempt> attempts
) {}
