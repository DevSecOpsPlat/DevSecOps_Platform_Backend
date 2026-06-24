package com.backend.devsecopsplatform_backend.service.admin.dto;

import java.util.List;

public record AdminAuditPageResponse(
        List<AdminAuditLogResponse> items,
        long totalElements,
        int totalPages,
        int page,
        int size
) {}
