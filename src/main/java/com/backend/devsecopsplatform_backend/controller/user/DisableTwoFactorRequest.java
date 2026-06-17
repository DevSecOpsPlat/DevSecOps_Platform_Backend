package com.backend.devsecopsplatform_backend.controller.user;

public record DisableTwoFactorRequest(String code, String currentPassword) {}
