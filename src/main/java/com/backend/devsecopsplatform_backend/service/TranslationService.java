package com.backend.devsecopsplatform_backend.service;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

@Service
@Slf4j
public class TranslationService {

    private static final int MYMEMORY_MAX_CHARS = 480;
    private static final Pattern HTML_BLOCK_SPLIT =
            Pattern.compile("(?<=</(?:p|li|h[1-6]|div|td|tr|ul|ol|pre|code)>)", Pattern.CASE_INSENSITIVE);

    private final RestTemplate restTemplate = new RestTemplate();
    private final Map<String, String> cache = new ConcurrentHashMap<>();

    @Value("${translation.enabled:true}")
    private boolean enabled;

    /** mymemory (gratuit, sans clé) | libretranslate (nécessite api-key) */
    @Value("${translation.provider:mymemory}")
    private String provider;

    @Value("${translation.mymemory.email:}")
    private String myMemoryEmail;

    @Value("${libretranslate.url:https://libretranslate.com}")
    private String libreTranslateUrl;

    @Value("${libretranslate.api-key:}")
    private String libreTranslateApiKey;

    /**
     * Traduit un texte de l'anglais vers le français.
     * Cache par {@code cacheKey} pour éviter les appels répétés.
     */
    public String translateToFrench(String text, String cacheKey) {
        if (!enabled || text == null || text.isBlank()) {
            return text;
        }
        if (isProbablyFrench(text)) {
            return text;
        }

        String key = "rule_" + normalizeProvider() + "_" + cacheKey;
        String cached = cache.get(key);
        if (cached != null) {
            return cached;
        }

        TranslationResult result = translateWithProvider(text, cacheKey);
        if (result.success()) {
            cache.put(key, result.text());
            return result.text();
        }
        // Ne pas cacher les échecs : permet de réessayer plus tard (quota, réseau, provider changé).
        return text;
    }

    private TranslationResult translateWithProvider(String text, String cacheKey) {
        if ("libretranslate".equalsIgnoreCase(provider) && libreTranslateApiKey != null && !libreTranslateApiKey.isBlank()) {
            String translated = translateWithLibreTranslate(text, cacheKey);
            if (translated != null && !translated.isBlank() && !translated.equals(text)) {
                return TranslationResult.success(translated);
            }
        }
        return translateWithMyMemory(text, cacheKey);
    }

    private TranslationResult translateWithMyMemory(String text, String cacheKey) {
        try {
            StringBuilder result = new StringBuilder();
            for (String chunk : chunkForTranslation(text)) {
                URI uri = UriComponentsBuilder
                        .fromHttpUrl("https://api.mymemory.translated.net/get")
                        .queryParam("q", chunk)
                        .queryParam("langpair", "en|fr")
                        .queryParamIfPresent("de", optionalEmail())
                        .build()
                        .encode()
                        .toUri();

                JsonNode body = restTemplate.getForObject(uri, JsonNode.class);
                if (body == null) {
                    log.warn("MyMemory : réponse vide pour {}", cacheKey);
                    return TranslationResult.failure(text);
                }
                if (body.path("quotaFinished").asBoolean(false)) {
                    log.warn("MyMemory : quota journalier épuisé pour {}", cacheKey);
                    return TranslationResult.failure(text);
                }
                String status = body.path("responseStatus").asText("200");
                if (!"200".equals(status)) {
                    String details = body.path("responseDetails").asText("");
                    log.warn("MyMemory erreur {} pour {} : {}", status, cacheKey, details);
                    return TranslationResult.failure(text);
                }
                String part = body.path("responseData").path("translatedText").asText("");
                if (part.isBlank()) {
                    return TranslationResult.failure(text);
                }
                result.append(part);
            }
            log.debug("Traduction MyMemory OK cacheKey={} ({} car.)", cacheKey, result.length());
            return TranslationResult.success(result.toString());
        } catch (Exception e) {
            log.warn("Erreur traduction MyMemory pour {} : {}", cacheKey, e.getMessage());
            return TranslationResult.failure(text);
        }
    }

    private java.util.Optional<String> optionalEmail() {
        if (myMemoryEmail == null || myMemoryEmail.isBlank()) {
            return java.util.Optional.empty();
        }
        return java.util.Optional.of(myMemoryEmail.trim());
    }

    private String translateWithLibreTranslate(String text, String cacheKey) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            Map<String, Object> requestBody = new LinkedHashMap<>();
            requestBody.put("q", text);
            requestBody.put("source", "en");
            requestBody.put("target", "fr");
            requestBody.put("format", "html");
            requestBody.put("api_key", libreTranslateApiKey.trim());

            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);
            String url = libreTranslateUrl.replaceAll("/+$", "") + "/translate";

            ResponseEntity<JsonNode> response = restTemplate.postForEntity(url, entity, JsonNode.class);
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                String translated = response.getBody().path("translatedText").asText();
                if (!translated.isBlank()) {
                    log.debug("Traduction LibreTranslate OK cacheKey={}", cacheKey);
                    return translated;
                }
            }
        } catch (Exception e) {
            log.warn("Erreur traduction LibreTranslate pour {} : {}", cacheKey, e.getMessage());
        }
        return text;
    }

    List<String> chunkForTranslation(String text) {
        List<String> chunks = new ArrayList<>();
        if (text.length() <= MYMEMORY_MAX_CHARS) {
            chunks.add(text);
            return chunks;
        }

        String[] blocks = HTML_BLOCK_SPLIT.split(text);
        StringBuilder current = new StringBuilder();
        for (String block : blocks) {
            if (block.isEmpty()) {
                continue;
            }
            if (block.length() > MYMEMORY_MAX_CHARS) {
                if (current.length() > 0) {
                    chunks.add(current.toString());
                    current = new StringBuilder();
                }
                chunks.addAll(hardSplit(block, MYMEMORY_MAX_CHARS));
                continue;
            }
            if (current.length() + block.length() > MYMEMORY_MAX_CHARS) {
                chunks.add(current.toString());
                current = new StringBuilder(block);
            } else {
                current.append(block);
            }
        }
        if (current.length() > 0) {
            chunks.add(current.toString());
        }
        return chunks.isEmpty() ? List.of(text) : chunks;
    }

    private List<String> hardSplit(String text, int maxLen) {
        List<String> parts = new ArrayList<>();
        int start = 0;
        while (start < text.length()) {
            int end = Math.min(start + maxLen, text.length());
            if (end < text.length()) {
                int breakAt = text.lastIndexOf(' ', end);
                if (breakAt > start + maxLen / 2) {
                    end = breakAt;
                }
            }
            parts.add(text.substring(start, end));
            start = end;
        }
        return parts;
    }

    private boolean isProbablyFrench(String text) {
        if (text == null || text.isBlank()) {
            return false;
        }
        String plain = text.replaceAll("<[^>]+>", " ").replaceAll("\\s+", " ").trim();
        int accents = 0;
        for (int i = 0; i < plain.length(); i++) {
            if ("éèêëàâôîïûùçœÉÈÊËÀÂÔÎÏÛÙÇŒ".indexOf(plain.charAt(i)) >= 0) {
                accents++;
            }
        }
        if (plain.length() < 60) {
            return accents >= 1;
        }
        // Texte long : un seul mot français ne suffit pas (évite les hybrides EN + « vulnérabilités »).
        if (accents < 3) {
            return false;
        }
        String lower = plain.toLowerCase();
        int frenchWords = 0;
        for (String w : new String[]{" les ", " des ", " une ", " pour ", " dans ", " cette ", " doit ", " sont ", " avec ", " pas "}) {
            if (lower.contains(w)) {
                frenchWords++;
            }
        }
        return frenchWords >= 2 || accents >= 6;
    }

    private String normalizeProvider() {
        if (provider == null || provider.isBlank()) {
            return "mymemory";
        }
        return provider.trim().toLowerCase();
    }

    private record TranslationResult(String text, boolean success) {
        static TranslationResult success(String text) {
            return new TranslationResult(text, true);
        }

        static TranslationResult failure(String original) {
            return new TranslationResult(original, false);
        }
    }
}
