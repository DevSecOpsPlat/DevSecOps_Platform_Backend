package com.backend.devsecopsplatform_backend.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;

/**
 * Connaissances RAG par pipeline : contexte d'application généré automatiquement
 * par le CI (stage reporting) + documents additionnels déposés manuellement.
 * Stockage disque, rechargé à chaud à chaque appel — pas de cache, pas de rebuild.
 *
 * Arborescence :
 *   ${ai.knowledge.dir}/apps/{appServiceId}/{branch}/context.md   ← généré par le pipeline
 *   ${ai.knowledge.dir}/apps/{appServiceId}/{branch}/docs/*.md    ← docs manuelles optionnelles
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class PipelineKnowledgeService {

    private static final int MAX_CONTEXT_CHARS = 4_000;
    private static final int MAX_DOC_CHARS = 3_000;

    @Value("${ai.knowledge.dir:./knowledge}")
    private String knowledgeDir;

    public void updatePipelineContext(UUID applicationId, String branch, String markdownContext) {
        try {
            Path dir = appDir(applicationId, branch);
            Files.createDirectories(dir);
            Files.writeString(dir.resolve("context.md"),
                    markdownContext == null ? "" : markdownContext,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            log.info("[KNOWLEDGE] Contexte pipeline mis à jour app={} branch={}", applicationId, branch);
        } catch (IOException e) {
            log.warn("[KNOWLEDGE] Écriture contexte échouée app={} branch={}: {}",
                    applicationId, branch, e.getMessage());
        }
    }

    /**
     * Bloc PIPELINE_CONTEXT à injecter systématiquement dans le prompt ("" si absent).
     * Fallback : si aucun contexte pour la branche demandée, on tente la branche "main".
     */
    public String getPipelineContextBlock(UUID applicationId, String branch) {
        if (applicationId == null) return "";
        String content = readSafely(appDir(applicationId, branch).resolve("context.md"), MAX_CONTEXT_CHARS);
        if (content.isBlank() && branch != null && !"main".equals(branch)) {
            content = readSafely(appDir(applicationId, "main").resolve("context.md"), MAX_CONTEXT_CHARS);
        }
        if (content.isBlank()) return "";
        return "PIPELINE_CONTEXT (stack et configuration réelles du projet analysé — source prioritaire) :\n"
                + content + "\n";
    }

    public List<String> retrieveAppDocs(UUID applicationId, String branch, String findingText, int max) {
        if (applicationId == null || max <= 0) return List.of();
        Path docsDir = appDir(applicationId, branch).resolve("docs");
        if (!Files.isDirectory(docsDir)) return List.of();
        Set<String> queryTokens = tokenize(findingText);
        record Scored(String content, long score) {}
        List<Scored> scored = new ArrayList<>();
        try (Stream<Path> files = Files.list(docsDir)) {
            files.filter(p -> p.toString().endsWith(".md")).forEach(p -> {
                String c = readSafely(p, MAX_DOC_CHARS);
                if (c.isBlank()) return;
                Set<String> docTokens = tokenize(c);
                long overlap = queryTokens.stream().filter(docTokens::contains).count();
                if (overlap >= 2) scored.add(new Scored(c, overlap));
            });
        } catch (IOException e) {
            log.warn("[KNOWLEDGE] Lecture docs app={} échouée: {}", applicationId, e.getMessage());
        }
        scored.sort((a, b) -> Long.compare(b.score(), a.score()));
        return scored.stream().limit(max).map(Scored::content).toList();
    }

    private Path appDir(UUID applicationId, String branch) {
        String safeBranch = (branch == null || branch.isBlank() ? "main" : branch)
                .replaceAll("[^a-zA-Z0-9._-]", "_");
        return Path.of(knowledgeDir, "apps", applicationId.toString(), safeBranch);
    }

    private String readSafely(Path f, int maxChars) {
        try {
            if (!Files.isRegularFile(f)) return "";
            String s = Files.readString(f, StandardCharsets.UTF_8);
            return s.length() > maxChars ? s.substring(0, maxChars) + "\n[...tronqué]" : s;
        } catch (IOException e) {
            return "";
        }
    }

    private static Set<String> tokenize(String s) {
        if (s == null) return Set.of();
        Set<String> out = new HashSet<>();
        for (String t : s.toLowerCase(Locale.ROOT).split("[^a-z0-9./@_-]+")) {
            if (t.length() >= 4) out.add(t);
        }
        return out;
    }
}
