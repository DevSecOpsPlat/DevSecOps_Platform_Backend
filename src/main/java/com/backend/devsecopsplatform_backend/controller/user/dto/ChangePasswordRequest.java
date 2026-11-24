package com.backend.devsecopsplatform_backend.controller.user.dto;

public record ChangePasswordRequest(
        String currentPassword,
        String newPassword
) {}
