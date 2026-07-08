package com.backend.devsecopsplatform_backend.controller.finding;

import lombok.Data;

/**
 * Optionnel : extrait de code autour de la vulnérabilité (copié depuis l'IDE ou le dépôt).
 * Réduit la dépendance au quota : on n'envoie pas tout le rapport, seulement ce finding + ce snippet.
 */
@Data
public class FindingAiRemediationRequest {
    /** Extrait de fichier (lignes concernées ou fichier complet si petit). Max appliqué côté serveur. */
    private String codeSnippet;
    /** Si true : ignore le template statique et envoie un prompt IA complet (Groq/OpenRouter/Ollama). */
    private boolean deepAnalysis;
}
