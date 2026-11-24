package com.backend.devsecopsplatform_backend.controller.user.dto;

public record UpdateEmailRequest(
        String email,
        String currentPassword
) {}
