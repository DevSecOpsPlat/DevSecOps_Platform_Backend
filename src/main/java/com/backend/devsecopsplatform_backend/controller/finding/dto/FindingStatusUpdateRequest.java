package com.backend.devsecopsplatform_backend.controller.finding.dto;

import com.backend.devsecopsplatform_backend.entity.finding.FindingStatus;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class FindingStatusUpdateRequest {
    @NotNull
    private FindingStatus status;
}
