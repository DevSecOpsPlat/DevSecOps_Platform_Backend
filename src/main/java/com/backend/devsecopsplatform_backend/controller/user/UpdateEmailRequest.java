package com.backend.devsecopsplatform_backend.controller.user;

public record UpdateEmailRequest(
        String email,
        String currentPassword
) {}
