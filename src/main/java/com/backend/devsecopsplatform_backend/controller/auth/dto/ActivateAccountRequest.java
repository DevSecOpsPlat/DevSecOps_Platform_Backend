package com.backend.devsecopsplatform_backend.controller.auth.dto;

public record ActivateAccountRequest(
        String token,
        String newPassword
) {}
