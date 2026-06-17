package com.backend.devsecopsplatform_backend.service.admin.dto;

public record AdminAuditDayCount(
        String date,
        long count
) {}
