package com.backend.devsecopsplatform_backend.service.admin.dto;

import java.util.List;

public record AdminAlertPageResponse(
        List<AdminAlertResponse> items,
        long totalElements,
        int totalPages,
        int page,
        int size
) {}
