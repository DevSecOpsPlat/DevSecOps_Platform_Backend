package com.backend.devsecopsplatform_backend.controller.finding;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class FindingChatMessageDto {
    /** "user" ou "assistant" */
    @NotBlank
    private String role;
    @NotBlank
    private String content;
}
