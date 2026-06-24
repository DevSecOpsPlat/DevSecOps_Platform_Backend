package com.backend.devsecopsplatform_backend.controller.user;

public record ChangePasswordRequest(
        String currentPassword,
        String newPassword
) {}
