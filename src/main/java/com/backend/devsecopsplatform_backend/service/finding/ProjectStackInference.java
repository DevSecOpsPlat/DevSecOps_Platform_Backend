package com.backend.devsecopsplatform_backend.service.finding;

import com.backend.devsecopsplatform_backend.entity.Application;
import com.backend.devsecopsplatform_backend.entity.Finding;
import com.backend.devsecopsplatform_backend.entity.FindingOccurrence;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Déduit des indices de stack à partir du projet (application), du finding et d'un extrait optionnel,
 * pour que les prompts IA proposent des commandes et exemples adaptés (npm vs mvn vs pip, etc.).
 */
public final class ProjectStackInference {

    private ProjectStackInference() {
    }

    public static String buildBlock(Finding f, FindingOccurrence occ, Application app, String codeSnippet) {
        Set<String> hints = new LinkedHashSet<>();
        if (app != null) {
            String name = nullToEmpty(app.getName()).strip();
            if (!name.isEmpty()) {
                hints.add("Projet testé (nom) : " + name);
            }
            String desc = nullToEmpty(app.getDescription()).strip();
            if (!desc.isEmpty() && desc.length() <= 500) {
                hints.add("Description projet (plateforme) : " + desc);
            } else if (!desc.isEmpty()) {
                hints.add("Description projet (tronquée) : " + desc.substring(0, 500) + "…");
            }
            String git = nullToEmpty(app.getGitRepositoryUrl()).toLowerCase(Locale.ROOT);
            if (git.contains("github.com")) {
                hints.add("Dépôt : GitHub");
            } else if (git.contains("gitlab")) {
                hints.add("Dépôt : GitLab");
            }
        }
        if (occ != null) {
            addPathSignals(nullToEmpty(occ.getArtifactPath()), hints);
        }
        if (f != null) {
            addPathSignals(nullToEmpty(f.getFilePath()), hints);
            addPackageSignals(nullToEmpty(f.getPackageName()), hints);
        }
        addSnippetSignals(nullToEmpty(codeSnippet), hints);

        if (hints.isEmpty()) {
            return "TECHNOLOGIES_DEDUITES : (aucun indice fort — rester générique ou se baser sur filePath/packageName du finding)\n";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("TECHNOLOGIES_DEDUITES (adapter commandes et exemples à cette stack ; si ambigu, le dire) :\n");
        for (String h : hints) {
            sb.append("- ").append(h).append("\n");
        }
        return sb.toString();
    }

    private static void addPathSignals(String path, Set<String> hints) {
        if (path.isEmpty()) {
            return;
        }
        String p = path.replace('\\', '/').toLowerCase(Locale.ROOT);
        if (p.contains("package.json") || p.contains("package-lock.json") || p.contains("yarn.lock")
                || p.contains("pnpm-lock") || p.contains("node_modules/")) {
            hints.add("Node.js / écosystème npm (indices chemins)");
        }
        if (p.contains("angular.json") || p.contains("/.angular/")) {
            hints.add("Angular (indices chemins)");
        }
        if (p.contains("next.config") || p.contains("next/")) {
            hints.add("Next.js (indices chemins)");
        }
        if (p.contains("vite.config") || p.contains("vitest.config")) {
            hints.add("Vite (indices chemins)");
        }
        if (p.contains("pom.xml") || p.endsWith(".java") || p.contains("/src/main/java/")
                || p.contains("/target/") || p.contains("maven")) {
            hints.add("Java / Maven (indices chemins)");
        }
        if (p.contains("build.gradle") || p.contains("settings.gradle") || p.contains(".gradle")) {
            hints.add("Java / Gradle (indices chemins)");
        }
        if (p.contains("requirements.txt") || p.contains("setup.py") || p.contains("pyproject.toml")
                || p.endsWith(".py")) {
            hints.add("Python (indices chemins)");
        }
        if (p.contains("go.mod") || p.endsWith(".go")) {
            hints.add("Go (indices chemins)");
        }
        if (p.contains("cargo.toml") || p.endsWith(".rs")) {
            hints.add("Rust (indices chemins)");
        }
        if (p.contains("composer.json") || p.endsWith(".php")) {
            hints.add("PHP (indices chemins)");
        }
        if (p.endsWith(".csproj") || p.endsWith(".sln") || p.endsWith(".cs")) {
            hints.add(".NET / C# (indices chemins)");
        }
        if (p.contains("gemfile") || p.endsWith(".rb")) {
            hints.add("Ruby (indices chemins)");
        }
        if (p.endsWith(".html") || p.endsWith(".htm") || p.contains(".vue") || p.contains(".svelte")) {
            hints.add("Front web / markup (HTML, Vue, Svelte… — indices chemins)");
        }
        if (p.contains("dockerfile") || p.contains("container")) {
            hints.add("Conteneur / Docker (indices chemins)");
        }
    }

    private static void addPackageSignals(String pkg, Set<String> hints) {
        if (pkg.isEmpty()) {
            return;
        }
        String lower = pkg.toLowerCase(Locale.ROOT);
        if (lower.startsWith("@angular/") || lower.equals("angular")) {
            hints.add("Package npm lié à Angular");
        }
        if (lower.startsWith("react") || lower.contains("react-dom")) {
            hints.add("Écosystème React (nom de package)");
        }
        if (lower.startsWith("org.springframework") || lower.contains("spring-boot")) {
            hints.add("Java Spring (nom de package Maven)");
        }
        if (lower.contains("django") || lower.contains("flask") || lower.contains("fastapi")) {
            hints.add("Framework Python (nom de package)");
        }
    }

    private static void addSnippetSignals(String snippet, Set<String> hints) {
        if (snippet.length() < 20) {
            return;
        }
        String s = snippet.toLowerCase(Locale.ROOT);
        if (s.contains("import react") || s.contains("from \"react\"") || s.contains("from 'react'")) {
            hints.add("React (extrait de code)");
        }
        if (s.contains("@angular") || s.contains("angular.core")) {
            hints.add("Angular (extrait de code)");
        }
        if (s.contains("public static void main") || s.contains("package ") && s.contains(";")) {
            hints.add("Java (extrait de code)");
        }
        if (s.contains("def ") && s.contains(":") && (s.contains("import ") || s.contains("print("))) {
            hints.add("Python (extrait de code — heuristique)");
        }
        if (s.contains("<template") && s.contains("vue")) {
            hints.add("Vue (extrait de code — heuristique)");
        }
    }

    private static String nullToEmpty(String s) {
        return s != null ? s : "";
    }
}
