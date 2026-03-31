package com.backend.devsecopsplatform_backend.controller.finding;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class FindingAiRemediationResponse {
    private String problemSummary;
    private String impact;
    private String location;
    @Builder.Default
    private List<String> remediationSteps = new ArrayList<>();
    /** Diff ou bloc de code suggéré (remplacement de fonction, patch). */
    private String suggestedPatch;
    /** Si pertinent : exemple de fichier entier corrigé ; peut être vide. */
    private String fullFileRewrite;
    @Builder.Default
    private List<String> verificationHints = new ArrayList<>();
    /** Commandes concrètes à lancer (shell, npm, mvn, scanner, CI local…) pour valider le correctif. */
    @Builder.Default
    private List<String> verificationCommands = new ArrayList<>();
    /** Si le modèle n'a pas respecté le JSON strict. */
    private String rawModelOutput;
    /** MANUAL (collé par l'utilisateur), GITHUB, GITLAB, NONE — origine du contexte code envoyé au modèle. */
    private String codeContextSource;
}
