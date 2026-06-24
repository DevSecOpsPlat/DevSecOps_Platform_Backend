package com.backend.devsecopsplatform_backend.controller.ai;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Réponse de l'analyse IA d'un artifact : résumé global + liste des vulnérabilités
 * avec description, emplacement et remédiation.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AnalyzeArtifactResponse {

    /** Résumé global de l'analyse (nombre de vulnérabilités, état général). */
    private String summary;

    /** Liste des vulnérabilités / problèmes avec titre, sévérité, emplacement, description, remédiation. */
    private List<VulnerabilityItem> vulnerabilities;
}
