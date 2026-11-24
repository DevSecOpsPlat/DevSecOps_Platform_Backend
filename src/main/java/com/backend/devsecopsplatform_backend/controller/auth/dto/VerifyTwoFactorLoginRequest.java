package com.backend.devsecopsplatform_backend.controller.auth.dto;

public record VerifyTwoFactorLoginRequest(String pendingLoginId, String code) {}
