package com.backend.devsecopsplatform_backend.controller.user;

import java.util.List;
import java.util.UUID;

public record ProfileResponse(
        UUID id,
        String username,
        String email,
        List<String> roles,
        String accountStatus,
        String createdAt,
        boolean twoFactorEnabled,
        boolean mustEnableTwoFactor,
        String twoFactorMethod
) {}
