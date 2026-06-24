package com.backend.devsecopsplatform_backend.controller.admin;

import jakarta.validation.constraints.NotBlank;

public record BlockIpRequest(
        @NotBlank String ip,
        String reason,
        Integer minutes
) {}
