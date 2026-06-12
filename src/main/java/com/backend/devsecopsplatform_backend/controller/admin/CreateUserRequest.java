package com.backend.devsecopsplatform_backend.controller.admin;

import com.backend.devsecopsplatform_backend.entity.Role;

public record CreateUserRequest(
        String username,
        String email,
        String password,
        Role role
) {}
