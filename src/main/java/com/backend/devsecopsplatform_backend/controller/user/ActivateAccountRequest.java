package com.backend.devsecopsplatform_backend.controller.user;

public record ActivateAccountRequest(
        String token,
        String newPassword
) {}
