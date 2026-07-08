package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.DbEngine;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Vérifie qu'un tag d'image officielle existe sur Docker Hub.
 * <ul>
 *   <li>{@link Result#NOT_FOUND} → bloquer (404 définitif)</li>
 *   <li>{@link Result#UNKNOWN} → laisser passer (timeout / 429 / réseau)</li>
 *   <li>{@link Result#EXISTS} → OK</li>
 * </ul>
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class ImageTagAvailabilityService {

    public enum Result { EXISTS, NOT_FOUND, UNKNOWN }

    private static final Duration CACHE_TTL = Duration.ofHours(6);
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(4);

    private final ObjectMapper objectMapper;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(HTTP_TIMEOUT)
            .build();

    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public Result check(DbEngine engine, String version) {
        if (engine == null || version == null || version.isBlank()) {
            return Result.UNKNOWN;
        }
        String tag = version.trim();
        String key = engine.name() + ":" + tag;
        CacheEntry cached = cache.get(key);
        if (cached != null && cached.expiresAt.isAfter(Instant.now())) {
            return cached.result;
        }

        Result result = fetch(engine, tag);
        if (result != Result.UNKNOWN) {
            cache.put(key, new CacheEntry(result, Instant.now().plus(CACHE_TTL)));
        }
        return result;
    }

    private Result fetch(DbEngine engine, String tag) {
        String repo = AppDatabaseRules.dockerHubRepo(engine);
        // API Hub v2 tags/list est lourde ; endpoint léger tags/{tag}
        String url = "https://hub.docker.com/v2/repositories/" + repo + "/tags/" + tag;
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(HTTP_TIMEOUT)
                    .GET()
                    .header("Accept", "application/json")
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            int code = response.statusCode();
            if (code == 200) {
                JsonNode node = objectMapper.readTree(response.body());
                if (node.has("name") || node.has("id")) {
                    return Result.EXISTS;
                }
                return Result.EXISTS;
            }
            if (code == 404) {
                return Result.NOT_FOUND;
            }
            log.warn("Docker Hub tag check {} → HTTP {} (UNKNOWN)", AppDatabaseRules.imageRef(engine, tag), code);
            return Result.UNKNOWN;
        } catch (Exception e) {
            log.warn("Docker Hub tag check {} échoué (UNKNOWN): {}",
                    AppDatabaseRules.imageRef(engine, tag), e.getMessage());
            return Result.UNKNOWN;
        }
    }

    private record CacheEntry(Result result, Instant expiresAt) {
    }
}
