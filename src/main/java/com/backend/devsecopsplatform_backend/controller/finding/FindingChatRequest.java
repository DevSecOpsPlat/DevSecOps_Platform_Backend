package com.backend.devsecopsplatform_backend.controller.finding;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;

@Data
public class FindingChatRequest {
    @NotEmpty
    @Valid
    private List<FindingChatMessageDto> messages;

    /** Résumé optionnel de la dernière remédiation IA affichée (texte libre). */
    private String remediationSummary;
}
