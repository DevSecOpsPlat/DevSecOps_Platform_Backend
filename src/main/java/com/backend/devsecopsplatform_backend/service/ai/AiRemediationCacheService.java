package com.backend.devsecopsplatform_backend.service.ai;

import com.backend.devsecopsplatform_backend.controller.finding.FindingAiRemediationResponse;
import com.backend.devsecopsplatform_backend.entity.AiRemediationCache;
import com.backend.devsecopsplatform_backend.repository.AiRemediationCacheRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class AiRemediationCacheService {

    private final AiRemediationCacheRepository repository;
    private final ObjectMapper objectMapper;

    public String computeCacheKey(String ruleKey, String filePath, Integer line, String codeSnippet, boolean deepAnalysis) {
        String normSnippet = CodeContextExtractor.normalizeForCacheKey(codeSnippet);
        String payload = (ruleKey != null ? ruleKey.strip().toLowerCase() : "")
                + "|" + (filePath != null ? filePath.strip() : "")
                + "|" + (line != null ? line : "")
                + "|" + (deepAnalysis ? "deep" : "std")
                + "|" + normSnippet;
        return sha256(payload);
    }

    @Transactional(readOnly = true)
    public Optional<FindingAiRemediationResponse> get(String cacheKey) {
        return repository.findByCacheKey(cacheKey).map(entry -> {
            try {
                FindingAiRemediationResponse resp = objectMapper.readValue(entry.getResponseJson(), FindingAiRemediationResponse.class);
                return resp.toBuilder()
                        .responseSource("CACHE")
                        .aiProviderUsed(entry.getProvider() != null ? entry.getProvider() : resp.getAiProviderUsed())
                        .aiModelUsed(entry.getModel() != null ? entry.getModel() : resp.getAiModelUsed())
                        .quotaFallbackUsed(false)
                        .build();
            } catch (Exception e) {
                log.warn("Cache IA illisible pour clé {}: {}", cacheKey, e.getMessage());
                return null;
            }
        }).filter(r -> r != null);
    }

    @Transactional
    public void touchHit(String cacheKey) {
        repository.findByCacheKey(cacheKey).ifPresent(entry -> {
            entry.setHitCount(entry.getHitCount() + 1);
            repository.save(entry);
        });
    }

    @Transactional
    public void put(String cacheKey, FindingAiRemediationResponse response, String sourceType, String provider, String model) {
        try {
            String json = objectMapper.writeValueAsString(stripTransientFields(response));
            AiRemediationCache entry = repository.findByCacheKey(cacheKey).orElseGet(AiRemediationCache::new);
            entry.setCacheKey(cacheKey);
            entry.setResponseJson(json);
            entry.setSourceType(sourceType);
            entry.setProvider(provider);
            entry.setModel(model);
            if (entry.getHitCount() == 0) {
                entry.setHitCount(0);
            }
            repository.save(entry);
        } catch (Exception e) {
            log.warn("Impossible de mettre en cache la remédiation IA: {}", e.getMessage());
        }
    }

    private static FindingAiRemediationResponse stripTransientFields(FindingAiRemediationResponse r) {
        return r.toBuilder()
                .jobId(null)
                .status(null)
                .responseSource(null)
                .build();
    }

    private static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
