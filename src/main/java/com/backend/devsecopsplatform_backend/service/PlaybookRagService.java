package com.backend.devsecopsplatform_backend.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * RAG local "light" : sélectionne des playbooks selon le contexte texte.
 * v2 : les playbooks sont lus en priorité depuis le disque (${ai.knowledge.dir}/global/...),
 * modifiables à chaud sans rebuild, avec fallback sur le classpath (comportement historique).
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class PlaybookRagService {

    @Value("${ai.knowledge.dir:./knowledge}")
    private String knowledgeDir;

    private record Rule(String id, int weight, String resourcePath, List<String> mustContainAny, List<String> boostsIfContainAny) {}

    private final List<Rule> rules = List.of(
            new Rule(
                    "sast-semgrep",
                    75,
                    "playbooks/sast_semgrep.md",
                    List.of("scantype: sast", "toolname: semgrep", "semgrep"),
                    List.of("ruleid:", "owasp", "xss", "sql", "ssrf", "path traversal",
                            "deserial", "command injection", "crypto")
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
                    List.of("script", "stylesheet", "cdn", "link rel", "crossorigin",
                            "sha-384", "sha384", "sha256")
            ),
            new Rule(
                    "sca-dependency",
                    80,
                    "playbooks/sca_dependency.md",
                    List.of("scantype: sca",
                            "npm", "package-lock", "yarn.lock", "pnpm-lock", "node_modules",
                            "maven", "pom.xml", "gradle", "groupid", "artifactid",
                            "pip-audit", "safety", "requirements.txt", "pyproject.toml", "poetry.lock",
                            "nuget", ".csproj", "packages.lock.json",
                            "go.mod", "go.sum", "cargo.toml", "cargo.lock",
                            "composer.json", "composer.lock"),
                    List.of("packagename:", "installedversion:", "fixedversion:",
                            "cve-", "osv", "npm audit", "dependency", "transitive", "spring")
            ),
            new Rule(
                    "secrets",
                    90,
                    "playbooks/secrets_hardcoded.md",
                    List.of("scantype: secrets", "toolname: gitleaks", "gitleaks",
                            "secret", "token", "api key", "hardcoded"),
                    List.of("cognito", "aws", "github", "gitlab", "react", "vite",
                            "private key", "password")
            ),
            new Rule(
                    "container-grype",
                    70,
                    "playbooks/container_grype.md",
                    List.of("scantype: container", "toolname: grype", "grype"),
                    List.of("dockerfile", "from ", "apk", "apt", "yum", "cve-",
                            "alpine", "debian", "base image")
            ),
            new Rule(
                    "iac-checkov",
                    70,
                    "playbooks/iac_checkov.md",
                    List.of("scantype: iac", "toolname: checkov", "checkov", "terraform", ".tf", "ckv_"),
                    List.of("kubernetes", "rbac", "public", "encryption", "s3", "bucket",
                            "securitycontext", "privileged", "runasnonroot", "iam")
            ),
            new Rule(
                    "license-compliance",
                    70,
                    "playbooks/license_compliance.md",
                    List.of("scantype: license", "toolname: license", "license:", "licence:", "spdx"),
                    List.of("gpl", "agpl", "lgpl", "copyleft", "proprietary", "unknown license",
                            "incompatible", "forbidden", "blacklist", "whitelist", "notice")
            ),
            new Rule(
                    "dast-zap",
                    75,
                    "playbooks/dast_zap.md",
                    List.of("scantype: dast", "toolname: zap", "owasp zap", "zap baseline", "zap scan"),
                    List.of("content-security-policy", "csp", "x-frame-options", "hsts",
                            "strict-transport", "x-content-type", "cookie", "header",
                            "anti-csrf", "cors", "referrer-policy")
            ),
            new Rule(
                    "dockerfile-hadolint",
                    75,
                    "playbooks/dockerfile_hadolint.md",
                    List.of("toolname: hadolint", "hadolint", "scantype: dockerfile"),
                    List.of("dockerfile", "dl3", "dl4", "sc2", "from ", "apt-get", "apk add",
                            "user root", "latest", "pin")
            ),
            new Rule(
                    "sonarqube-quality",
                    70,
                    "playbooks/code_quality_sonarqube.md",
                    List.of("toolname: sonarqube", "sonarqube", "sonar scanner",
                            "security hotspot", "code smell"),
                    List.of("bug", "maintainability", "reliability", "cognitive complexity",
                            "duplicated", "java:s", "typescript:s", "python:s", "hotspot")
            )
    );

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

    /**
     * v2 : lecture disque prioritaire ( ${ai.knowledge.dir}/global/playbooks/xxx.md ),
     * fallback classpath (resources/playbooks/xxx.md) pour ne rien casser.
     */
    private String readResource(String path) {
        try {
            Path p = Path.of(knowledgeDir, "global", path);
            if (Files.isRegularFile(p)) {
                return Files.readString(p, StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            log.debug("Lecture disque playbook {} échouée: {}", path, e.getMessage());
        }
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
