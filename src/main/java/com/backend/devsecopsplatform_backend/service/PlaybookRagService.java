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

    // Un playbook par outil réellement actif dans le pipeline (Semgrep, Trivy, Gitleaks, Grype, Checkov,
    // Hadolint, SonarQube, ZAP). Le nom de l'outil figure toujours dans le contexte du finding
    // (« Outil / scan: … »), ce qui suffit à ouvrir la porte du bon playbook.
    // Poids commun 70. Deux priorités seulement, pour les findings qui ouvrent deux portes :
    // Secrets (90) passe devant Semgrep, qui détecte aussi des secrets ; Trivy (95) passe devant Secrets.
    private final List<Rule> rules = List.of(
            new Rule(
                    "sast-semgrep",
                    70,
                    "playbooks/sast_semgrep.md",
                    List.of("scantype: sast", "toolname: semgrep", "semgrep"),
                    List.of("ruleid:", "owasp", "xss", "sql", "ssrf", "path traversal",
                            "deserial", "command injection", "crypto", "integrity", "subresource")
            ),
            new Rule(
                    // Trivy ne tourne qu'en mode vulnérabilités (--scanners vuln) : ses findings sont des
                    // dépendances. Poids 95 > Secrets (90) : la description d'un CVE peut contenir « secret »
                    // (ex. jsonwebtoken, argument secretOrPublicKey) sans être une fuite de secret.
                    "trivy-fs",
                    95,
                    "playbooks/sca_trivy_fs.md",
                    List.of("toolname: trivy", "trivy", "artifactpath: reports/trivy"),
                    List.of("vulnerability", "cve-", "package", "dependency", "fixed",
                            "lock", "pom.xml", "package.json", "requirements")
            ),
            new Rule(
                    // « token » seul n'ouvre plus ce playbook (bibliothèques jsonwebtoken, csrf-token…) :
                    // il reste un mot bonus. Les règles Semgrep de secrets contiennent « secret » ou « hardcoded ».
                    "secrets",
                    90,
                    "playbooks/secrets_hardcoded.md",
                    List.of("scantype: secrets", "toolname: gitleaks", "gitleaks",
                            "secret", "api key", "hardcoded"),
                    List.of("cognito", "aws", "github", "gitlab", "react", "vite",
                            "private key", "password", "token")
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
                    "dast-zap",
                    70,
                    "playbooks/dast_zap.md",
                    List.of("scantype: dast", "toolname: zap", "owasp zap", "zap baseline", "zap scan"),
                    List.of("content-security-policy", "csp", "x-frame-options", "hsts",
                            "strict-transport", "x-content-type", "cookie", "header",
                            "anti-csrf", "cors", "referrer-policy", "integrity", "subresource")
            ),
            new Rule(
                    "dockerfile-hadolint",
                    70,
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
