package com.backend.devsecopsplatform_backend.service.admin.dto;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.LocalDateTime;
import java.util.UUID;

/** Détail d'une tentative de connexion échouée (vue admin). */
public record AdminFailedLoginEntry(
        UUID userId,
        String username,
        String email,
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
        LocalDateTime attemptedAt,
        String ipAddress
) {}
