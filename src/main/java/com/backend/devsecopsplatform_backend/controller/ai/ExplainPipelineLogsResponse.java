package com.backend.devsecopsplatform_backend.controller.ai;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Réponse IA : résumé + causes probables + actions (sans kubectl / accès cluster).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExplainPipelineLogsResponse {

    /** Réponse principale (style assistant, en français). */
    private String answer;

    /** Ce qui s'est passé, en 2–4 phrases. */
    private String summary;

    /** Causes probables, ordonnées du plus au moins probable. */
    private List<String> probableCauses;

    /**
     * Actions concrètes pour un testeur / développeur
     * (pas de kubectl ; UI plateforme, code, CI, ops si besoin).
     */
    private List<String> suggestedActions;
}
