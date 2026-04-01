package com.backend.devsecopsplatform_backend.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * RAG local "light" : sélectionne des playbooks versionnés dans resources/ selon le contexte texte.
 * Pas d'embeddings, pas de DB externe : juste des règles + contenu markdown copiable.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class PlaybookRagService {

    private record Rule(String id, int weight, String resourcePath, List<String> mustContainAny, List<String> boostsIfContainAny) {}

    private final List<Rule> rules = List.of(
            new Rule(
                    "sast-semgrep",
                    75,
                    "playbooks/sast_semgrep.md",
                    List.of("scantype: sast", "toolname: semgrep", "semgrep"),
                    List.of("ruleid:", "owasp", "xss", "sql", "ssrf", "path traversal")
            ),
            new Rule(
                    "trivy-fs",
                    60,
                    "playbooks/sca_trivy_fs.md",
                    List.of("toolname: trivy", "trivy", "artifactpath: reports/trivy"),
                    List.of("vulnerability", "misconfig", "secret", "cve-", "package")
            ),
            new Rule(
                    "sri-missing-integrity",
                    100,
                    "playbooks/sri_missing_integrity.md",
                    List.of("integrity", "subresource"),
                    List.of("script", "stylesheet", "cdn", "link rel", "crossorigin", "sha-384", "sha384", "sha256")
            ),
            new Rule(
                    "sca-npm",
                    80,
                    "playbooks/sca_npm_dependency.md",
                    List.of("scantype: sca", "npm", "package-lock", "yarn.lock", "pnpm-lock", "node_modules"),
                    List.of("packageName:", "installedVersion:", "fixedVersion:", "osv", "npm audit")
            ),
            new Rule(
                    "sca-python",
                    80,
                    "playbooks/sca_python_dependency.md",
                    List.of("scantype: sca", "pip-audit", "safety", "requirements.txt", "pyproject.toml"),
                    List.of("cve-", "fix_versions", "installed_version", "packageName:")
            ),
            new Rule(
                    "sca-maven",
                    80,
                    "playbooks/sca_maven_dependency.md",
                    List.of("scantype: sca", "maven", "pom.xml", "groupid", "artifactid"),
                    List.of("spring", "dependency:tree", "versions:")
            ),
            new Rule(
                    "secrets",
                    90,
                    "playbooks/secrets_hardcoded.md",
                    List.of("scantype: secrets", "secret", "token", "api key", "hardcoded"),
                    List.of("cognito", "aws", "github", "gitlab", "react", "vite")
            ),
            new Rule(
                    "container-grype",
                    70,
                    "playbooks/container_grype.md",
                    List.of("scantype: container", "toolname: grype", "grype"),
                    List.of("dockerfile", "from ", "apk", "apt", "yum", "cve-")
            ),
            new Rule(
                    "iac-checkov",
                    70,
                    "playbooks/iac_checkov.md",
                    List.of("scantype: iac", "toolname: checkov", "checkov", "terraform", ".tf"),
                    List.of("kubernetes", "rbac", "public", "encryption", "s3", "bucket")
            ),
            new Rule(
                    "license-compliance",
                    70,
                    "playbooks/license_compliance.md",
                    List.of("scantype: license", "toolname: license", "license:", "licence:", "spdx"),
                    List.of("gpl", "agpl", "lgpl", "copyleft", "proprietary", "unknown license", "incompatible", "forbidden", "blacklist", "whitelist", "notice")
            )
    );

    /**
     * Retourne 0..N playbooks markdown pertinents à inclure dans le prompt.
     */
    public List<String> retrievePlaybooks(String fullContextText, int max) {
        String t = (fullContextText == null ? "" : fullContextText).toLowerCase(Locale.ROOT);
        if (t.isBlank() || max <= 0) {
            return List.of();
        }
        List<ScoredRule> matches = new ArrayList<>();
        for (Rule r : rules) {
            int score = score(r, t);
            if (score > 0) {
                matches.add(new ScoredRule(r, score));
            }
        }
        matches.sort((a, b) -> Integer.compare(b.score, a.score));

        List<String> out = new ArrayList<>();
        for (int i = 0; i < matches.size() && out.size() < max; i++) {
            String content = readResource(matches.get(i).rule.resourcePath);
            if (content != null && !content.isBlank()) {
                out.add(content.trim());
            }
        }
        return out;
    }

    private record ScoredRule(Rule rule, int score) {}

    private int score(Rule r, String t) {
        boolean anyMust = false;
        for (String k : r.mustContainAny) {
            if (t.contains(k)) {
                anyMust = true;
                break;
            }
        }
        if (!anyMust) {
            return 0;
        }
        int s = r.weight;
        for (String b : r.boostsIfContainAny) {
            if (t.contains(b)) {
                s += 8;
            }
        }
        return s;
    }

    private String readResource(String path) {
        try {
            ClassPathResource res = new ClassPathResource(path);
            if (!res.exists()) {
                log.warn("Playbook introuvable: {}", path);
                return null;
            }
            byte[] bytes = res.getInputStream().readAllBytes();
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.warn("Lecture playbook échouée {}: {}", path, e.getMessage());
            return null;
        }
    }
}

