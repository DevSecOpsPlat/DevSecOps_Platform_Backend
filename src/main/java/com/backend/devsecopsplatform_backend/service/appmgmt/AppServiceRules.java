package com.backend.devsecopsplatform_backend.service.appmgmt;

import com.backend.devsecopsplatform_backend.entity.appmgmt.AppServiceRole;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Règles métier pour les services managés : formats, bornes, capacités par rôle.
 */
public final class AppServiceRules {

    public static final int MIN_EXPOSED_PORT = 1024;
    public static final int MAX_EXPOSED_PORT = 65535;
    public static final int MAX_REPLICAS = 5;
    public static final long MAX_MEMORY_MIB = 8L * 1024; // 8 Gi
    public static final long MAX_CPU_MILLICORES = 4000; // 4 CPU

    /** HTTPS Git uniquement — refuse git://, ssh://, ext:: (RCE via git clone). */
    public static final Pattern GIT_HTTPS_URL = Pattern.compile(
            "^https://[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%\\-]+$",
            Pattern.CASE_INSENSITIVE
    );

    /** Chemin relatif sûr pour Dockerfile / build context. */
    public static final Pattern RELATIVE_PATH = Pattern.compile(
            "^(?!/)(?!.*\\.\\.)(?!-)[A-Za-z0-9._/\\-]+$"
    );

    /** Identifiant C pour clé d'env K8s. */
    public static final Pattern ENV_VAR_KEY = Pattern.compile("^[A-Za-z_][A-Za-z0-9_]*$");

    public static final Pattern CPU_QUANTITY = Pattern.compile(
            "^([0-9]+(\\.[0-9]+)?)(m)?$"
    );

    public static final Pattern MEMORY_QUANTITY = Pattern.compile(
            "^([0-9]+)(E|P|T|G|M|K|Ei|Pi|Ti|Gi|Mi|Ki)?$"
    );

    private static final Set<String> RESERVED_ENV_KEYS = Set.of(
            "PATH", "HOME", "HOSTNAME", "TERM", "LANG", "PWD", "SHLVL", "OLDPWD",
            "KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT",
            "KUBERNETES_PORT", "KUBERNETES_PORT_443_TCP"
    );

    private AppServiceRules() {
    }

    public static boolean canDependOnDatabase(AppServiceRole role) {
        return role == AppServiceRole.BACKEND || role == AppServiceRole.WORKER;
    }

    public static boolean requiresExposedPort(AppServiceRole role) {
        return role == AppServiceRole.FRONTEND || role == AppServiceRole.BACKEND;
    }

    public static boolean allowsHealthCheck(AppServiceRole role) {
        return role == AppServiceRole.FRONTEND || role == AppServiceRole.BACKEND;
    }

    public static boolean isExternallyExposed(AppServiceRole role) {
        return role == AppServiceRole.FRONTEND || role == AppServiceRole.BACKEND;
    }

    public static void assertGitHttpsUrl(String url) {
        if (url == null || url.isBlank()) {
            throw new AppValidationException("L'URL du repository Git est obligatoire.");
        }
        String u = url.trim();
        String lower = u.toLowerCase(Locale.ROOT);
        if (lower.startsWith("ext::") || lower.startsWith("git://") || lower.startsWith("ssh://")
                || lower.startsWith("file://") || lower.contains("ext::")) {
            throw new AppValidationException(
                    "URL Git refusée : seuls les dépôts HTTPS sont autorisés "
                            + "(git://, ssh://, ext:: et file:// sont bloqués).");
        }
        if (!GIT_HTTPS_URL.matcher(u).matches()) {
            throw new AppValidationException(
                    "URL Git invalide : utilisez une URL HTTPS (ex. https://github.com/org/repo).");
        }
    }

    public static void assertRelativePath(String path, String fieldLabel) {
        if (path == null || path.isBlank()) {
            return;
        }
        String p = path.trim();
        if (p.contains("..") || p.startsWith("/") || p.startsWith("\\")
                || p.contains(" ") || p.startsWith("-")
                || !RELATIVE_PATH.matcher(p).matches()) {
            throw new AppValidationException(
                    fieldLabel + " invalide : chemin relatif requis, sans « .. », espace ni chemin absolu "
                            + "(ex. Dockerfile, ./Dockerfile, backend/).");
        }
    }

    public static void assertEnvVarKey(String key) {
        if (key == null || key.isBlank()) {
            throw new AppValidationException("La clé de variable d'environnement est obligatoire.");
        }
        String k = key.trim();
        if (!ENV_VAR_KEY.matcher(k).matches()) {
            throw new AppValidationException(
                    "Clé d'environnement invalide « " + k
                            + " » : doit être un identifiant C (lettres, chiffres, _, pas de tiret).");
        }
        if (RESERVED_ENV_KEYS.contains(k) || k.startsWith("KUBERNETES_")) {
            throw new AppValidationException(
                    "La clé d'environnement « " + k + " » est réservée et ne peut pas être définie.");
        }
    }

    public static long cpuToMillicores(String raw) {
        if (raw == null || raw.isBlank()) {
            return 100;
        }
        Matcher m = CPU_QUANTITY.matcher(raw.trim());
        if (!m.matches()) {
            throw new AppValidationException(
                    "Quantité CPU invalide « " + raw + " » (ex. 100m, 0.5, 1).");
        }
        double n = Double.parseDouble(m.group(1));
        boolean milli = m.group(3) != null;
        long mills = milli ? Math.round(n) : Math.round(n * 1000);
        if (mills <= 0) {
            throw new AppValidationException("CPU doit être > 0.");
        }
        return mills;
    }

    public static long memoryToMib(String raw) {
        if (raw == null || raw.isBlank()) {
            return 128;
        }
        Matcher m = MEMORY_QUANTITY.matcher(raw.trim());
        if (!m.matches()) {
            throw new AppValidationException(
                    "Quantité mémoire invalide « " + raw + " » (ex. 128Mi, 1Gi).");
        }
        long n = Long.parseLong(m.group(1));
        String unit = m.group(2) == null ? "" : m.group(2);
        long bytes = switch (unit) {
            case "Ki" -> n * 1024L;
            case "Mi" -> n * 1024L * 1024L;
            case "Gi" -> n * 1024L * 1024L * 1024L;
            case "Ti" -> n * 1024L * 1024L * 1024L * 1024L;
            case "K" -> n * 1000L;
            case "M" -> n * 1000L * 1000L;
            case "G" -> n * 1000L * 1000L * 1000L;
            case "", "E", "P", "T", "Ei", "Pi" -> n; // octets ou unités exotiques ≈ octets
            default -> n;
        };
        long mib = Math.max(1, bytes / (1024L * 1024L));
        if (unit.isEmpty() && n < 1024) {
            // nombre nu ambigu — traiter comme Mi pour UX (128 → 128Mi)
            mib = n;
        }
        return mib;
    }

    public static void validateQuantities(
            String cpuRequest, String cpuLimit,
            String memoryRequest, String memoryLimit
    ) {
        long cpuReq = cpuToMillicores(cpuRequest);
        long cpuLim = cpuToMillicores(cpuLimit);
        if (cpuReq > cpuLim) {
            throw new AppValidationException(
                    "CPU request (" + cpuRequest + ") ne peut pas dépasser CPU limit (" + cpuLimit + ").");
        }
        if (cpuLim > MAX_CPU_MILLICORES) {
            throw new AppValidationException(
                    "CPU limit trop élevé (max " + (MAX_CPU_MILLICORES / 1000) + " cœurs).");
        }

        long memReq = memoryToMib(memoryRequest);
        long memLim = memoryToMib(memoryLimit);
        if (memReq > memLim) {
            throw new AppValidationException(
                    "Mémoire request (" + memoryRequest + ") ne peut pas dépasser la limite (" + memoryLimit + ").");
        }
        if (memLim > MAX_MEMORY_MIB) {
            throw new AppValidationException(
                    "Mémoire limit trop élevée (max " + (MAX_MEMORY_MIB / 1024) + "Gi).");
        }
    }
}
