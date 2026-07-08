package com.backend.devsecopsplatform_backend.service.ai;

import com.backend.devsecopsplatform_backend.controller.finding.FindingAiRemediationResponse;
import com.backend.devsecopsplatform_backend.controller.finding.ReferenceItem;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Recommandations pré-validées pour vulnérabilités courantes (CWE / mots-clés).
 * Évite un appel IA lorsque le pattern est reconnu avec confiance.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class StaticRemediationTemplateService {

    private static final Pattern CWE_PATTERN = Pattern.compile("CWE[- ]?(\\d+)", Pattern.CASE_INSENSITIVE);

    private final ObjectMapper objectMapper;
    private List<TemplateEntry> templates = List.of();

    @PostConstruct
    void loadTemplates() {
        try (InputStream in = new ClassPathResource("remediation-templates.json").getInputStream()) {
            JsonNode root = objectMapper.readTree(in);
            List<TemplateEntry> loaded = new ArrayList<>();
            for (JsonNode node : root) {
                loaded.add(parseEntry(node));
            }
            templates = List.copyOf(loaded);
            log.info("[AI] {} modèles de remédiation statiques chargés", templates.size());
        } catch (Exception e) {
            log.warn("[AI] remediation-templates.json non chargé: {}", e.getMessage());
            templates = List.of();
        }
    }

    public Optional<FindingAiRemediationResponse> match(String findingContext, boolean deepAnalysis) {
        if (deepAnalysis || findingContext == null || findingContext.isBlank()) {
            return Optional.empty();
        }
        String ctx = findingContext.toLowerCase(Locale.ROOT);
        Set<String> cwes = extractCwes(findingContext);

        TemplateEntry best = null;
        int bestScore = 0;
        for (TemplateEntry t : templates) {
            int score = t.score(ctx, cwes);
            if (score > bestScore) {
                bestScore = score;
                best = t;
            }
        }
        if (best == null || bestScore < 3) {
            return Optional.empty();
        }
        log.info("[AI] Remédiation statique '{}' (score={})", best.id, bestScore);
        return Optional.of(best.toResponse());
    }

    public static String extractRuleKey(String findingContext) {
        if (findingContext == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        Matcher cwe = CWE_PATTERN.matcher(findingContext);
        while (cwe.find()) {
            sb.append("cwe-").append(cwe.group(1)).append('|');
        }
        String title = extractLineValue(findingContext, "Titre:");
        if (title != null) {
            sb.append(title.strip().toLowerCase(Locale.ROOT));
        }
        return sb.toString();
    }

    private static Set<String> extractCwes(String ctx) {
        Set<String> out = new HashSet<>();
        Matcher m = CWE_PATTERN.matcher(ctx);
        while (m.find()) {
            out.add(m.group(1));
        }
        return out;
    }

    private static String extractLineValue(String ctx, String prefix) {
        for (String line : ctx.split("\n")) {
            if (line.startsWith(prefix)) {
                return line.substring(prefix.length()).trim();
            }
        }
        return null;
    }

    private TemplateEntry parseEntry(JsonNode node) {
        List<String> cwes = new ArrayList<>();
        node.path("match").path("cwe").forEach(n -> cwes.add(n.asText()));
        List<String> keywords = new ArrayList<>();
        node.path("match").path("keywords").forEach(n -> keywords.add(n.asText().toLowerCase(Locale.ROOT)));
        JsonNode resp = node.path("response");
        return new TemplateEntry(
                node.path("id").asText(),
                cwes,
                keywords,
                resp.path("problemSummary").asText(""),
                resp.path("rootCause").asText(""),
                resp.path("impact").asText(""),
                resp.path("businessRisk").asText(""),
                resp.path("location").asText(""),
                resp.path("reproduction").asText(""),
                readStringList(resp.path("remediationSteps")),
                resp.path("suggestedPatch").asText(""),
                resp.path("secureCodeBefore").asText(""),
                resp.path("secureCodeAfter").asText(""),
                readStringList(resp.path("bestPractices")),
                readReferences(resp.path("references")),
                readStringList(resp.path("verificationHints")),
                readStringList(resp.path("verificationCommands")),
                resp.path("confidence").asText("HIGH")
        );
    }

    private List<String> readStringList(JsonNode arr) {
        if (!arr.isArray()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        arr.forEach(n -> out.add(n.asText()));
        return out;
    }

    private List<ReferenceItem> readReferences(JsonNode arr) {
        if (!arr.isArray()) {
            return List.of();
        }
        List<ReferenceItem> out = new ArrayList<>();
        arr.forEach(n -> out.add(ReferenceItem.builder()
                .type(n.path("type").asText("CWE"))
                .id(n.path("id").asText(""))
                .url(n.path("url").asText(""))
                .build()));
        return out;
    }

    private record TemplateEntry(
            String id,
            List<String> cwes,
            List<String> keywords,
            String problemSummary,
            String rootCause,
            String impact,
            String businessRisk,
            String location,
            String reproduction,
            List<String> remediationSteps,
            String suggestedPatch,
            String secureCodeBefore,
            String secureCodeAfter,
            List<String> bestPractices,
            List<ReferenceItem> references,
            List<String> verificationHints,
            List<String> verificationCommands,
            String confidence
    ) {
        int score(String ctxLower, Set<String> ctxCwes) {
            int s = 0;
            for (String cwe : cwes) {
                String num = cwe.replaceAll("\\D", "");
                if (ctxCwes.contains(num)) {
                    s += 5;
                }
            }
            for (String kw : keywords) {
                if (ctxLower.contains(kw)) {
                    s += 2;
                }
            }
            return s;
        }

        FindingAiRemediationResponse toResponse() {
            return FindingAiRemediationResponse.builder()
                    .problemSummary(problemSummary)
                    .rootCause(rootCause)
                    .impact(impact)
                    .businessRisk(businessRisk)
                    .location(location)
                    .reproduction(reproduction)
                    .remediationSteps(remediationSteps)
                    .suggestedPatch(suggestedPatch)
                    .secureCodeBefore(secureCodeBefore)
                    .secureCodeAfter(secureCodeAfter)
                    .bestPractices(bestPractices)
                    .references(references)
                    .verificationHints(verificationHints)
                    .verificationCommands(verificationCommands)
                    .confidence(confidence)
                    .responseSource("STATIC")
                    .aiProviderUsed("static-template")
                    .aiModelUsed(id)
                    .quotaFallbackUsed(false)
                    .aiModelTier("DEFAULT")
                    .build();
        }
    }
}
