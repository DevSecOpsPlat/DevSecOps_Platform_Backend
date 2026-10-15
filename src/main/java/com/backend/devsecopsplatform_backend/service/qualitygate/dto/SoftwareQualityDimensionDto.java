package com.backend.devsecopsplatform_backend.service.qualitygate.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SoftwareQualityDimensionDto {
    /** SECURITY | RELIABILITY | MAINTAINABILITY */
    private String dimension;
    private int issues;
    /** Note A–E (convertie depuis rating Sonar 1–5). */
    private String rating;
    /**
     * Note numérique 1–5, ou {@code null} si {@link #rating} est aussi {@code null} -- jamais 0
     * (0 n'est pas une note Sonar valide ; c'était auparavant le symbole "inconnu" côté backend,
     * mais un {@code int} primitif l'exposait comme une vraie valeur JSON, indiscernable d'une
     * note réelle côté frontend).
     */
    private Integer ratingValue;
    /**
     * High / Medium / Low depuis measures/component (métriques SQ dédiées Sonar 10+).
     * Absent si métriques indisponibles (Sonar &lt; 10) — pas de re-calcul issues/search ici.
     */
    private Map<String, Integer> bySeverity;
}
