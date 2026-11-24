package com.backend.devsecopsplatform_backend.controller.auth.dto;

public record EnableTwoFactorRequest(String code, String currentPassword) {}
