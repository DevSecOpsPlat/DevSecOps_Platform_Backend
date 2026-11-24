package com.backend.devsecopsplatform_backend.controller.admin.dto;

import com.backend.devsecopsplatform_backend.entity.user.Role;

public record CreateUserRequest(
        String username,
        String email,
        Role role
) {}
