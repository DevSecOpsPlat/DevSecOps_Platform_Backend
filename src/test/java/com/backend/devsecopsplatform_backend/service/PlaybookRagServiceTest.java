package com.backend.devsecopsplatform_backend.service;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Sélection des playbooks : un playbook par outil réellement actif dans le pipeline.
 * Les contextes reprennent le format de DefectDojoService.buildAiContext (+ extrait de code).
 * Sans ai.knowledge.dir, les playbooks sont lus dans le classpath (resources/playbooks).
 */
class PlaybookRagServiceTest {

    private final PlaybookRagService rag = new PlaybookRagService();

    private static String ctx(String titre, String outil, String fichier, String description) {
        return "Source: DefectDojo\nTitre: " + titre + "\nSévérité: High\nOutil / scan: " + outil
                + "\nFichier: " + fichier + "\nDescription scanner:\n" + description + "\n";
    }

    private String first(String context) {
        List<String> hits = rag.retrievePlaybooks(context, 1);
        assertEquals(1, hits.size(), "un playbook attendu");
        return hits.get(0).lines().findFirst().orElse("");
    }

    @Test
    void cveDontLaDescriptionContientSecret_resteUnPlaybookTrivy() {
        String c = ctx("CVE-2022-23529 jsonwebtoken 8.5.1", "Trivy / Trivy Scan", "package-lock.json",
                "If an attacker controls the secretOrPublicKey argument of jwt.verify(), arbitrary file write is possible.");
        assertTrue(first(c).contains("Trivy"), first(c));
    }

    @Test
    void dependanceMaven_playbookTrivy() {
        String c = ctx("CVE-2022-22965 spring-beans 5.3.17", "Trivy / Trivy Scan", "pom.xml",
                "Spring MVC application may be vulnerable to remote code execution. Fixed version 5.3.18.");
        assertTrue(first(c).contains("Trivy"), first(c));
    }

    @Test
    void integriteManquanteSemgrep_playbookSemgrep() {
        String c = ctx("html.security.audit.missing-integrity.missing-integrity", "Semgrep / Semgrep JSON Report",
                "src/index.html", "This tag is missing an 'integrity' subresource integrity attribute.")
                + "\n12 | <script src=\"https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js\"></script>";
        String head = first(c);
        assertTrue(head.contains("Semgrep"), head);
        assertTrue(rag.retrievePlaybooks(c, 1).get(0).contains("integrity"), "section SRI présente dans le playbook Semgrep");
    }

    @Test
    void integriteManquanteZap_playbookZap() {
        String c = ctx("Sub Resource Integrity Attribute Missing", "ZAP / ZAP Scan", "",
                "The integrity attribute is missing on a script or link tag served by an external server.");
        assertTrue(first(c).contains("ZAP"), first(c));
    }

    @Test
    void secretGitleaks_playbookSecrets() {
        String c = ctx("aws-access-token", "Gitleaks / Gitleaks Scan", "config/application.yml",
                "Identified a pattern that may indicate AWS credentials.");
        assertTrue(first(c).contains("Secret"), first(c));
    }

    @Test
    void paquetNpmDansImage_playbookGrype() {
        String c = ctx("GHSA-c2qf-rxjj-qqgw semver 7.3.7", "Anchore Grype / Anchore Grype",
                "/app/node_modules/semver/package.json", "Package type: npm. Fixed in 7.5.2.");
        assertTrue(first(c).contains("Grype"), first(c));
    }

    @Test
    void huitPlaybooksTousPresentsSurLeClasspath() {
        String all = "semgrep trivy gitleaks grype checkov hadolint sonarqube zap scan";
        List<String> hits = rag.retrievePlaybooks(all, 20);
        assertEquals(8, hits.size(), "chaque règle doit pointer vers un playbook existant");
        assertTrue(hits.stream().noneMatch(h -> h.contains("Subresource Integrity (SRI) manquant")
                || h.contains("Problème de licence") || h.contains("Dépendance vulnérable (SCA — tous écosystèmes)")),
                "les playbooks retirés ne doivent plus être servis");
    }
}
