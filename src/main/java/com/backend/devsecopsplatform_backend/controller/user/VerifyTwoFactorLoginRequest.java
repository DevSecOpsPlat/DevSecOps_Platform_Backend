package com.backend.devsecopsplatform_backend.controller.user;

public record VerifyTwoFactorLoginRequest(String pendingLoginId, String code) {}
