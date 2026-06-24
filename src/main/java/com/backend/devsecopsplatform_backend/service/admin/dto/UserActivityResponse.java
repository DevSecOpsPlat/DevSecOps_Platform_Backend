package com.backend.devsecopsplatform_backend.service.admin.dto;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entrée du journal d'activité d'un compte (vue admin).
 */
public record UserActivityResponse(
        UUID id,
        String action,
        String detail,
        String performedBy,
        LocalDateTime createdAt
) {}
