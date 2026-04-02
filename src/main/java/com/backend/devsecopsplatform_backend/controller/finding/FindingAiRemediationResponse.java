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

    /** Provider réellement utilisé pour cet appel (groq | ollama | gemini | huggingface | ...). */
    private String aiProviderUsed;
    /** Nom/id du modèle réellement utilisé (ex: llama3-70b, deepseek-coder, gemini-1.5-pro...). */
    private String aiModelUsed;
    /**
     * Indique si un fallback automatique a été déclenché (ex: quota/429 Groq → Ollama).
     * Sert à expliquer à l'utilisateur pourquoi le modèle affiché peut changer.
     */
    private Boolean quotaFallbackUsed;
    /**
     * Etiquette simple pour l'UI (ex: HIGH). Demandé pour expliciter le “nouveau modèle” en cas de quota atteint.
     * Valeurs typiques : DEFAULT | HIGH.
     */
    private String aiModelTier;
}
