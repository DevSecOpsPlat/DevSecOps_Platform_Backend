package com.backend.devsecopsplatform_backend.service.admin.dto;

public record AdminLoginDayStats(
        String date,
        long success,
        long failed
) {}
