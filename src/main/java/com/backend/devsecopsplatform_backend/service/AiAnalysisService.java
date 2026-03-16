package com.backend.devsecopsplatform_backend.service;

import com.backend.devsecopsplatform_backend.controller.ai.AnalyzeArtifactResponse;
import com.backend.devsecopsplatform_backend.controller.ai.VulnerabilityItem;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Service d'analyse des artifacts par IA. Plusieurs fournisseurs supportés (sans carte bancaire) :
 * - groq : gratuit, clé sur console.groq.com (recommandé)
 * - huggingface : gratuit, token sur huggingface.co/settings/tokens
 * - ollama : local, pas de clé (ollama run llama2)
 * - gemini : Google (quota souvent limité en free tier)
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class AiAnalysisService {

    private static final String GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models/";
    private static final String GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";
    private static final String HUGGINGFACE_INFERENCE_URL = "https://api-inference.huggingface.co/models/";
    private static final String OLLAMA_DEFAULT_URL = "http://localhost:11434";
    /** Limite de caractères pour réduire la consommation de tokens. */
    private static final int MAX_ARTIFACT_LENGTH = 120_000;
    private static final int DEFAULT_RETRY_DELAY_SECONDS = 45;

    private final ObjectMapper objectMapper;

    /** gemini | groq | huggingface | ollama */
    @Value("${ai.provider:groq}")
    private String aiProvider;

    @Value("${ai.enabled:true}")
    private boolean aiEnabled;

    // Gemini
    @Value("${ai.gemini.api-key:}")
    private String geminiApiKey;
    @Value("${ai.gemini.model:gemini-2.0-flash}")
    private String geminiModel;

    // Groq (gratuit, sans carte - console.groq.com)
    @Value("${ai.groq.api-key:}")
    private String groqApiKey;
    @Value("${ai.groq.model:llama-3.3-70b-versatile}")
    private String groqModel;

    // Hugging Face (gratuit - huggingface.co/settings/tokens)
    @Value("${ai.huggingface.token:}")
    private String huggingfaceToken;
    @Value("${ai.huggingface.model:HuggingFaceH4/zephyr-7b-beta}")
    private String huggingfaceModel;

    // Ollama (local, pas de clé)
    @Value("${ai.ollama.url:http://localhost:11434}")
    private String ollamaUrl;
    @Value("${ai.ollama.model:llama2}")
    private String ollamaModel;

    /**
     * Analyse le contenu d'un artifact (JSON ou texte) et renvoie les vulnérabilités
     * détectées avec description, où les trouver et comment les corriger.
     *
     * @param artifactContent Contenu brut de l'artifact (rapport de scan).
     * @param artifactSource  Optionnel : type (trivy, sonarqube, etc.) pour aider l'IA.
     * @return Résumé + liste de vulnérabilités avec remédiation.
     */
    public AnalyzeArtifactResponse analyzeArtifact(String artifactContent, String artifactSource) {
        if (!aiEnabled) {
            return errorResponse("Analyse IA désactivée (ai.enabled=true pour activer).");
        }
        String provider = (aiProvider != null) ? aiProvider.strip().toLowerCase() : "groq";
        if (!isProviderConfigured(provider)) {
            return errorResponse("Provider '" + provider + "' non configuré. " + getConfigHint(provider));
        }

        String content = artifactContent;
        if (content.length() > MAX_ARTIFACT_LENGTH) {
            log.info("Artifact tronqué de {} à {} caractères", content.length(), MAX_ARTIFACT_LENGTH);
            content = content.substring(0, MAX_ARTIFACT_LENGTH) + "\n\n[... contenu tronqué ...]";
        }

        String sourceHint = (artifactSource != null && !artifactSource.isBlank())
                ? " (format probable: " + artifactSource + ")"
                : "";
        String prompt = buildPrompt(content, sourceHint);

        try {
            String jsonResponse = callAiProvider(provider, prompt);
            return parseGeminiResponse(jsonResponse);
        } catch (Exception e) {
            log.error("Erreur analyse IA ({}): {}", provider, e.getMessage());
            String userMessage = buildUserFriendlyErrorMessage(e, provider);
            return AnalyzeArtifactResponse.builder()
                    .summary(userMessage)
                    .vulnerabilities(List.of())
                    .build();
        }
    }

    private AnalyzeArtifactResponse errorResponse(String summary) {
        return AnalyzeArtifactResponse.builder().summary(summary).vulnerabilities(List.of()).build();
    }

    private boolean isProviderConfigured(String provider) {
        return switch (provider) {
            case "gemini" -> geminiApiKey != null && !geminiApiKey.isBlank();
            case "groq" -> groqApiKey != null && !groqApiKey.isBlank();
            case "huggingface" -> huggingfaceToken != null && !huggingfaceToken.isBlank();
            case "ollama" -> true; // pas de clé
            default -> false;
        };
    }

    private String getConfigHint(String provider) {
        return switch (provider) {
            case "gemini" -> "Définissez ai.gemini.api-key. Ou utilisez ai.provider=groq avec ai.groq.api-key (gratuit, console.groq.com).";
            case "groq" -> "Définissez ai.groq.api-key. Clé gratuite sur https://console.groq.com (pas de carte requise).";
            case "huggingface" -> "Définissez ai.huggingface.token sur https://huggingface.co/settings/tokens.";
            case "ollama" -> "Lancez Ollama localement : ollama run llama2. Ou utilisez ai.provider=groq.";
            default -> "Choisissez ai.provider=groq, huggingface, ollama ou gemini et configurez la clé correspondante.";
        };
    }

    private String callAiProvider(String provider, String prompt) throws Exception {
        return switch (provider) {
            case "gemini" -> callGeminiWithRetry(prompt);
            case "groq" -> callGroq(prompt);
            case "huggingface" -> callHuggingFace(prompt);
            case "ollama" -> callOllama(prompt);
            default -> throw new IllegalStateException("Provider inconnu: " + provider);
        };
    }

    private String buildPrompt(String artifactContent, String sourceHint) {
        return """
            Tu es un expert en sécurité applicative. Analyse ce rapport d'artifact de pipeline de sécurité%s.
            Identifie toutes les vulnérabilités ou problèmes de sécurité (CVE, faiblesses, dépendances vulnérables, etc.).
            Pour chaque élément, fournis :
            1) Un titre court
            2) La sévérité (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            3) L'emplacement (fichier, dépendance, ligne, composant - où le trouver)
            4) Une description du risque
            5) Comment corriger / remédiation concrète

            Réponds UNIQUEMENT avec un JSON valide, sans markdown ni texte autour, de la forme :
            {"summary": "résumé en une phrase du rapport (nombre de vulnérabilités, état)", "vulnerabilities": [{"title": "...", "severity": "...", "location": "...", "description": "...", "remediation": "..."}]}

            Contenu de l'artifact :
            %s
            """.formatted(sourceHint, artifactContent);
    }

    /**
     * Appelle l'API Gemini avec un retry en cas de 429 (quota dépassé).
     */
    private String callGeminiWithRetry(String prompt) throws Exception {
        try {
            return callGemini(prompt);
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.TOO_MANY_REQUESTS) {
                int delaySec = parseRetryDelaySeconds(e.getResponseBodyAsString());
                log.warn("Quota Gemini dépassée (429). Nouvel essai dans {} secondes.", delaySec);
                Thread.sleep(delaySec * 1000L);
                return callGemini(prompt);
            }
            throw e;
        }
    }

    /** Extrait "Please retry in X.XXs" ou utilise le délai par défaut. */
    private int parseRetryDelaySeconds(String responseBody) {
        if (responseBody != null) {
            Matcher m = Pattern.compile("retry in (\\d+(?:\\.\\d+)?)\\s*s", Pattern.CASE_INSENSITIVE).matcher(responseBody);
            if (m.find()) {
                return Math.min(90, (int) Math.ceil(Double.parseDouble(m.group(1))));
            }
        }
        return DEFAULT_RETRY_DELAY_SECONDS;
    }

    private String buildUserFriendlyErrorMessage(Exception e, String provider) {
        String msg = e.getMessage() != null ? e.getMessage() : "";
        if (msg.contains("429") || msg.contains("quota") || msg.contains("RESOURCE_EXHAUSTED")) {
            return "Quota API dépassé (" + provider + "). Réessayez dans 1 à 2 minutes. Ou testez un autre provider : ai.provider=groq (gratuit, console.groq.com).";
        }
        if (msg.contains("404") || msg.contains("NOT_FOUND")) {
            return "Modèle ou ressource introuvable. Vérifiez ai." + provider + ".model ou changez de provider (ex: ai.provider=groq).";
        }
        if (msg.contains("401") || msg.contains("Unauthorized")) {
            return "Clé API invalide (" + provider + "). Vérifiez ai." + (provider.equals("groq") ? "groq.api-key" : provider + ".api-key/token") + ".";
        }
        return "Erreur lors de l'analyse IA (" + provider + "): " + (msg.length() > 200 ? msg.substring(0, 200) + "..." : msg);
    }

    private String callGemini(String prompt) {
        String url = GEMINI_BASE_URL + geminiModel + ":generateContent?key=" + geminiApiKey;

        var body = new java.util.LinkedHashMap<String, Object>();
        body.put("contents", List.of(
                java.util.Map.of("parts", List.of(java.util.Map.of("text", prompt)))
        ));
        body.put("generationConfig", java.util.Map.of(
                "temperature", 0.2,
                "maxOutputTokens", 8192,
                "responseMimeType", "application/json"
        ));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Object> entity = new HttpEntity<>(body, headers);
        RestTemplate rest = new RestTemplate();
        ResponseEntity<JsonNode> response = rest.exchange(url, HttpMethod.POST, entity, JsonNode.class);

        if (response.getBody() == null) {
            throw new RuntimeException("Réponse Gemini vide");
        }
        JsonNode root = response.getBody();
        JsonNode candidates = root.path("candidates");
        if (candidates.isEmpty() || !candidates.get(0).has("content")) {
            JsonNode blockReason = candidates.isEmpty() ? null : candidates.get(0).path("finishReason");
            throw new RuntimeException("Gemini n'a pas renvoyé de contenu. finishReason: " + blockReason.asText("UNKNOWN"));
        }
        JsonNode parts = candidates.get(0).get("content").path("parts");
        if (parts.isEmpty() || !parts.get(0).has("text")) {
            throw new RuntimeException("Réponse Gemini sans texte");
        }
        return parts.get(0).get("text").asText();
    }

    private String callGroq(String prompt) {
        var body = new java.util.LinkedHashMap<String, Object>();
        body.put("model", groqModel);
        body.put("messages", List.of(
                java.util.Map.of("role", "user", "content", prompt)
        ));
        body.put("temperature", 0.2);
        body.put("max_tokens", 8192);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(groqApiKey);
        HttpEntity<Object> entity = new HttpEntity<>(body, headers);
        RestTemplate rest = new RestTemplate();
        ResponseEntity<JsonNode> response = rest.exchange(GROQ_URL, HttpMethod.POST, entity, JsonNode.class);
        if (response.getBody() == null) throw new RuntimeException("Réponse Groq vide");
        JsonNode choice = response.getBody().path("choices").path(0);
        String text = choice.path("message").path("content").asText(null);
        if (text == null) throw new RuntimeException("Groq n'a pas renvoyé de contenu");
        return extractJsonFromResponse(text);
    }

    /** Hugging Face Inference API - token sur huggingface.co/settings/tokens */
    private String callHuggingFace(String prompt) {
        String url = HUGGINGFACE_INFERENCE_URL + huggingfaceModel;
        var body = new java.util.LinkedHashMap<String, Object>();
        body.put("inputs", prompt);
        body.put("parameters", java.util.Map.of(
                "max_new_tokens", 4096,
                "return_full_text", false
        ));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(huggingfaceToken);
        HttpEntity<Object> entity = new HttpEntity<>(body, headers);
        RestTemplate rest = new RestTemplate();
        ResponseEntity<JsonNode> response = rest.exchange(url, HttpMethod.POST, entity, JsonNode.class);
        if (response.getBody() == null) throw new RuntimeException("Réponse Hugging Face vide");
        JsonNode resBody = response.getBody();
        String text = null;
        if (resBody.isArray() && resBody.size() > 0) {
            text = resBody.path(0).path("generated_text").asText(null);
        } else if (resBody.has("generated_text")) {
            text = resBody.path("generated_text").asText(null);
        }
        if (text == null) throw new RuntimeException("Hugging Face n'a pas renvoyé de texte");
        return extractJsonFromResponse(text);
    }

    /** Ollama : local, pas de clé - lancer « ollama run llama2 » */
    private String callOllama(String prompt) {
        String url = ollamaUrl.replaceAll("/+$", "") + "/api/generate";
        var body = new java.util.LinkedHashMap<String, Object>();
        body.put("model", ollamaModel);
        body.put("prompt", prompt);
        body.put("stream", false);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Object> entity = new HttpEntity<>(body, headers);
        RestTemplate rest = new RestTemplate();
        try {
            ResponseEntity<JsonNode> response = rest.exchange(url, HttpMethod.POST, entity, JsonNode.class);
            if (response.getBody() == null) throw new RuntimeException("Réponse Ollama vide");
            String text = response.getBody().path("response").asText(null);
            if (text == null) throw new RuntimeException("Ollama n'a pas renvoyé de contenu");
            return extractJsonFromResponse(text);
        } catch (org.springframework.web.client.ResourceAccessException e) {
            throw new RuntimeException("Ollama inaccessible à " + ollamaUrl + ". Lancez « ollama run " + ollamaModel + " ».", e);
        }
    }

    /** Extrait le JSON de la réponse (enlève markdown si présent). */
    private String extractJsonFromResponse(String text) {
        if (text == null) return "";
        String t = text.trim();
        if (t.startsWith("```json")) {
            t = t.replaceFirst("^```json\\s*", "").replaceAll("```\\s*$", "").trim();
        } else if (t.startsWith("```")) {
            t = t.replaceFirst("^```\\s*", "").replaceAll("```\\s*$", "").trim();
        }
        return t;
    }

    private AnalyzeArtifactResponse parseGeminiResponse(String jsonText) {
        String toParse = extractJsonFromResponse(jsonText);
        try {
            JsonNode root = objectMapper.readTree(toParse);
            String summary = root.path("summary").asText("Aucun résumé fourni.");
            JsonNode vulns = root.path("vulnerabilities");
            List<VulnerabilityItem> list = new ArrayList<>();
            if (vulns.isArray()) {
                for (JsonNode v : vulns) {
                    list.add(VulnerabilityItem.builder()
                            .title(v.path("title").asText(""))
                            .severity(v.path("severity").asText(""))
                            .location(v.path("location").asText(""))
                            .description(v.path("description").asText(""))
                            .remediation(v.path("remediation").asText(""))
                            .build());
                }
            }
            return AnalyzeArtifactResponse.builder()
                    .summary(summary)
                    .vulnerabilities(list)
                    .build();
        } catch (Exception e) {
            log.warn("Impossible de parser la réponse JSON de l'IA, retour brut: {}", e.getMessage());
            return AnalyzeArtifactResponse.builder()
                    .summary("L'IA a répondu mais le format n'a pas pu être parsé. Réponse brute: " + (toParse.length() > 500 ? toParse.substring(0, 500) + "..." : toParse))
                    .vulnerabilities(List.of())
                    .build();
        }
    }
}
