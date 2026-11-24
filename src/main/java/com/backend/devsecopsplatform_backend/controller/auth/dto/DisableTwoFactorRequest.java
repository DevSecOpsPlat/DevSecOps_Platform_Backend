package com.backend.devsecopsplatform_backend.controller.auth.dto;

public record DisableTwoFactorRequest(String code, String currentPassword) {}
