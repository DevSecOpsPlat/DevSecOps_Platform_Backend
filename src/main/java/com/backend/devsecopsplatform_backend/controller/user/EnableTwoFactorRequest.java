package com.backend.devsecopsplatform_backend.controller.user;

public record EnableTwoFactorRequest(String code, String currentPassword) {}
