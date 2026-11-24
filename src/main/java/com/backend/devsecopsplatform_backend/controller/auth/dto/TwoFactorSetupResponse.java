package com.backend.devsecopsplatform_backend.controller.auth.dto;

public record TwoFactorSetupResponse(
        String otpAuthUrl,
        String secret,
        String issuer
) {}
