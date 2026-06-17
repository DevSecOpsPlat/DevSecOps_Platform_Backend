package com.backend.devsecopsplatform_backend.service.admin.dto;

public record AdminAuditTopActor(
        String username,
        long count
) {}
