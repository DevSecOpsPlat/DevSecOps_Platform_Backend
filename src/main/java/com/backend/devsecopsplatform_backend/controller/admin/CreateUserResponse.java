package com.backend.devsecopsplatform_backend.controller.admin;

import java.util.List;
import java.util.UUID;

public record CreateUserResponse(
        UUID id,
        String username,
        String email,
        List<String> roles,
        String accountStatus,
        boolean activationEmailSent,
        String message,
        String activationLink
) {}
