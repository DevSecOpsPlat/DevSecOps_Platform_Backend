package com.backend.devsecopsplatform_backend.controller.user;

public record TwoFactorSetupResponse(
        String otpAuthUrl,
        String secret,
        String issuer
) {}
