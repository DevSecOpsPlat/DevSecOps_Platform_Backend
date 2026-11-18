package com.backend.devsecopsplatform_backend.service.defectdojo;

import com.backend.devsecopsplatform_backend.entity.AppService;
import com.backend.devsecopsplatform_backend.service.SourceSnippetFetcherService;
import com.backend.devsecopsplatform_backend.service.defectdojo.dto.DefectDojoFindingDetailResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Preuves pour un finding DAST (OWASP ZAP). ZAP teste l'application DÉPLOYÉE à travers son URL :
 * il observe des réponses HTTP, pas le code. Pour que l'IA ne devine pas, la plateforme ajoute :
 * <ol>
 *   <li>un contrôle HTTP des en-têtes sur l'URL analysée (adresses de la plateforme uniquement) ;</li>
 *   <li>la chaîne d'exposition réelle d'une application déployée par EnviroTest
 *       (Cloudflare → Ingress Traefik généré par la plateforme → conteneur) ;</li>
 *   <li>le fichier d'entrée de l'application, déduit du Dockerfile du dépôt (ex. CMD uvicorn main:app → main.py).</li>
 * </ol>
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class DastContextService {

    static final String CORS_TEST_ORIGIN = "https://origine-externe.example";
    private static final Duration TIMEOUT = Duration.ofSeconds(6);
    private static final long PROBE_TTL_MS = 120_000;
    private static final long ENTRY_TTL_MS = 300_000;

    /** En-têtes conservés (ordre d'affichage). */
    private static final List<String> KEPT_HEADERS = List.of(
            "strict-transport-security", "content-security-policy", "content-security-policy-report-only",
            "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy",
            "cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy",
            "access-control-allow-origin", "access-control-allow-credentials", "access-control-allow-methods",
            "access-control-allow-headers", "cache-control", "pragma", "expires", "set-cookie",
            "server", "x-powered-by", "content-type", "location");

    /** En-têtes de sécurité dont l'absence est signalée. */
    private static final List<String> EXPECTED_SECURITY_HEADERS = List.of(
            "strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options",
            "referrer-policy", "permissions-policy", "cross-origin-opener-policy", "cross-origin-embedder-policy");

    private static final Pattern LINE_NUMBER_PREFIX = Pattern.compile("^\\s*\\d+\\| ?");
    private static final Pattern ASGI_WSGI = Pattern.compile(
            "\\b(?:uvicorn|gunicorn|hypercorn|daphne|granian)\\b.*?\\b([A-Za-z_][\\w.]*)\\s*:\\s*[A-Za-z_]\\w*");
    private static final Pattern PYTHON_FILE = Pattern.compile("\\bpython[\\d.]*\\s+(?:-u\\s+)?([\\w./-]+\\.py)\\b");
    private static final Pattern PYTHON_MODULE = Pattern.compile("\\bpython[\\d.]*\\s+-m\\s+([A-Za-z_][\\w.]*)");
    private static final Pattern NODE_FILE = Pattern.compile("\\bnode\\s+([\\w./-]+\\.(?:m?js|cjs))\\b");
    private static final Pattern NGINX_CONF = Pattern.compile("(?im)^\\s*COPY\\s+(?:--\\S+\\s+)*(\\S+\\.conf)\\s+/etc/nginx/");
    private static final Pattern DOCKERFILE_HEADER = Pattern.compile("# Dockerfile du dépôt : (\\S+)");

    private final SourceSnippetFetcherService sourceSnippetFetcherService;

    @Value("${deployment.ingress.custom-base-domain:}")
    private String platformDomain;

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    private final Map<String, Cached<DefectDojoFindingDetailResponse.LiveHttpCheck>> probeCache = new ConcurrentHashMap<>();
    private final Map<String, Cached<Optional<EntryPoint>>> entryCache = new ConcurrentHashMap<>();

    private record Cached<T>(T value, long at) {
        boolean fresh(long ttl) {
            return System.currentTimeMillis() - at < ttl;
        }
    }

    /** Fichier d'entrée de l'application, déduit du Dockerfile. */
    public record EntryPoint(String path, String reason, String content, String source) {}

    /** Complète le détail d'un finding DAST (URL déjà résolues dans {@code analyzedUrls}). */
    public void enrich(DefectDojoFindingDetailResponse detail, AppService app, String branch) {
        if (detail == null || !detail.isDynamicFinding()) {
            return;
        }
        List<String> urls = detail.getAnalyzedUrls() != null ? detail.getAnalyzedUrls() : List.of();
        String target = urls.stream().filter(this::isPlatformUrl).findFirst().orElse(null);
        if (target != null) {
            detail.setLiveCheck(probe(target, isCorsFinding(detail)));
        } else if (!urls.isEmpty()) {
            detail.setLiveCheck(DefectDojoFindingDetailResponse.LiveHttpCheck.builder()
                    .url(urls.get(0))
                    .error("Adresse hors du domaine de la plateforme : contrôle automatique non effectué.")
                    .build());
        }

        Optional<EntryPoint> entry = Optional.empty();
        if (app != null && (detail.getCodeSnippet() == null || detail.getCodeSnippet().isBlank())) {
            entry = entryPoint(app, branch);
            entry.ifPresent(e -> {
                detail.setCodeSnippet(e.content());
                detail.setCodeContextSource(e.source());
                detail.setCodeFilePath(e.path());
                detail.setCodeContextHint(e.reason());
            });
        }
        if (target != null) {
            detail.setExposureChain(exposureChain(target, detail.getLiveCheck(), app, entry.orElse(null)));
        }
    }

    // ── Contrôle HTTP ─────────────────────────────────────────────────────────────────────────

    boolean isPlatformUrl(String url) {
        if (url == null || platformDomain == null || platformDomain.isBlank()) {
            return false;
        }
        try {
            URI uri = URI.create(url.trim());
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
            String domain = platformDomain.trim().toLowerCase(Locale.ROOT);
            boolean sameDomain = host.equals(domain) || host.endsWith("." + domain);
            return sameDomain && (scheme.equals("https") || scheme.equals("http"));
        } catch (Exception e) {
            return false;
        }
    }

    private DefectDojoFindingDetailResponse.LiveHttpCheck probe(String url, boolean corsTest) {
        String key = url + "|" + corsTest;
        Cached<DefectDojoFindingDetailResponse.LiveHttpCheck> hit = probeCache.get(key);
        if (hit != null && hit.fresh(PROBE_TTL_MS)) {
            return hit.value();
        }
        DefectDojoFindingDetailResponse.LiveHttpCheck result = doProbe(url, corsTest);
        probeCache.put(key, new Cached<>(result, System.currentTimeMillis()));
        return result;
    }

    private DefectDojoFindingDetailResponse.LiveHttpCheck doProbe(String url, boolean corsTest) {
        String checkedAt = Instant.now().toString();
        try {
            HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(url.trim()))
                    .timeout(TIMEOUT)
                    .header("User-Agent", "EnviroTest-SecurityCheck/1.0")
                    .header("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")
                    .GET();
            if (corsTest) {
                req.header("Origin", CORS_TEST_ORIGIN);
            }
            HttpResponse<Void> resp = http.send(req.build(), HttpResponse.BodyHandlers.discarding());
            Map<String, String> headers = new LinkedHashMap<>();
            for (String name : KEPT_HEADERS) {
                List<String> values = resp.headers().allValues(name);
                if (values.isEmpty()) continue;
                headers.put(name, "set-cookie".equals(name) ? maskCookies(values) : String.join(", ", values));
            }
            List<String> missing = EXPECTED_SECURITY_HEADERS.stream().filter(h -> !headers.containsKey(h)).toList();
            String error = null;
            if (isTraefikNotFound(resp.statusCode(), headers)) {
                error = "Aucune application ne répond sur cette adresse (environnement arrêté ou supprimé) : "
                        + "les en-têtes observés ne sont pas ceux de l'application scannée.";
            } else if (resp.statusCode() >= 500) {
                error = "L'application répond en erreur " + resp.statusCode() + " : contrôle peu fiable.";
            }
            return DefectDojoFindingDetailResponse.LiveHttpCheck.builder()
                    .url(url)
                    .status(resp.statusCode())
                    .checkedAt(checkedAt)
                    .headers(headers)
                    .missingHeaders(missing)
                    .corsTestOrigin(corsTest ? CORS_TEST_ORIGIN : null)
                    .error(error)
                    .build();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return failedProbe(url, checkedAt, "contrôle interrompu");
        } catch (Exception e) {
            log.debug("[DAST] Contrôle HTTP {} impossible : {}", url, e.getMessage());
            return failedProbe(url, checkedAt, "adresse injoignable (" + e.getClass().getSimpleName() + ")");
        }
    }

    private static DefectDojoFindingDetailResponse.LiveHttpCheck failedProbe(String url, String at, String why) {
        return DefectDojoFindingDetailResponse.LiveHttpCheck.builder()
                .url(url).checkedAt(at).error("Contrôle impossible : " + why + ".").build();
    }

    /** 404 « page not found » en texte brut : réponse par défaut de Traefik quand aucune route n'existe. */
    private static boolean isTraefikNotFound(int status, Map<String, String> headers) {
        String ct = headers.getOrDefault("content-type", "");
        return status == 404 && ct.startsWith("text/plain") && !headers.containsKey("content-security-policy");
    }

    /** Ne garde que le nom et les attributs des cookies (valeurs masquées). */
    private static String maskCookies(List<String> cookies) {
        List<String> out = new ArrayList<>();
        for (String c : cookies) {
            String[] parts = c.split(";");
            String first = parts[0].trim();
            int eq = first.indexOf('=');
            String name = eq > 0 ? first.substring(0, eq) : first;
            StringBuilder sb = new StringBuilder(name).append("=•••");
            for (int i = 1; i < parts.length; i++) {
                sb.append("; ").append(parts[i].trim());
            }
            out.add(sb.toString());
        }
        return String.join(" | ", out);
    }

    private static boolean isCorsFinding(DefectDojoFindingDetailResponse d) {
        String t = (d.getTitle() == null ? "" : d.getTitle()).toLowerCase(Locale.ROOT);
        return "10098".equals(d.getToolRuleId()) || t.contains("cross-domain") || t.contains("cors");
    }

    // ── Chaîne d'exposition ───────────────────────────────────────────────────────────────────

    private List<String> exposureChain(String url, DefectDojoFindingDetailResponse.LiveHttpCheck check,
                                       AppService app, EntryPoint entry) {
        String host;
        try {
            host = URI.create(url).getHost();
        } catch (Exception e) {
            host = url;
        }
        boolean cloudflareSeen = check != null && check.getHeaders() != null
                && check.getHeaders().getOrDefault("server", "").toLowerCase(Locale.ROOT).contains("cloudflare");
        List<String> chain = new ArrayList<>();
        chain.add("Cloudflare (tunnel) : TLS public et proxy vers le cluster"
                + (cloudflareSeen ? " — confirmé par l'en-tête « server: cloudflare »." : "."));
        chain.add("Traefik : Ingress Kubernetes généré par EnviroTest pour " + host
                + " — routage uniquement (aucun en-tête de sécurité ajouté) ; configuration de la plateforme, absente du dépôt.");
        String service = app != null && app.getName() != null ? " « " + app.getName() + " »" : "";
        chain.add("Conteneur du service" + service + " : l'application elle-même"
                + (entry != null ? " — point d'entrée " + entry.path() + " (" + entry.reason() + ")." : "."));
        return chain;
    }

    // ── Fichier d'entrée déduit du Dockerfile ────────────────────────────────────────────────

    Optional<EntryPoint> entryPoint(AppService app, String branch) {
        String key = app.getId() + "|" + (branch == null ? "" : branch);
        Cached<Optional<EntryPoint>> hit = entryCache.get(key);
        if (hit != null && hit.fresh(ENTRY_TTL_MS)) {
            return hit.value();
        }
        Optional<EntryPoint> found = Optional.empty();
        try {
            found = sourceSnippetFetcherService.tryFetchDockerfileFallback(app, branch)
                    .flatMap(docker -> locateEntryPoint(app, branch, docker.content()));
        } catch (Exception e) {
            log.debug("[DAST] Point d'entrée non déterminé (app={}) : {}", app.getId(), e.getMessage());
        }
        entryCache.put(key, new Cached<>(found, System.currentTimeMillis()));
        return found;
    }

    private Optional<EntryPoint> locateEntryPoint(AppService app, String branch, String dockerfileWithHeader) {
        String dockerPath = "Dockerfile";
        Matcher header = DOCKERFILE_HEADER.matcher(dockerfileWithHeader);
        if (header.find()) {
            dockerPath = header.group(1);
        }
        String dockerDir = dockerPath.contains("/") ? dockerPath.substring(0, dockerPath.lastIndexOf('/') + 1) : "";
        String dockerfile = stripLineNumbers(dockerfileWithHeader);

        Candidate c = candidateFromDockerfile(dockerfile);
        if (c == null) {
            return Optional.empty();
        }
        List<String> paths = new ArrayList<>();
        if (!dockerDir.isEmpty()) paths.add(dockerDir + c.path());
        paths.add(c.path());
        for (String path : paths) {
            Optional<SourceSnippetFetcherService.CodeSnippetFetch> file =
                    sourceSnippetFetcherService.tryFetchSnippetForRepository(app, branch, path, null, null);
            if (file.isPresent()) {
                String reason = "déduit de " + dockerPath + " : " + c.evidence();
                return Optional.of(new EntryPoint(path, reason, file.get().content(), file.get().source()));
            }
        }
        return Optional.empty();
    }

    record Candidate(String path, String evidence) {}

    static Candidate candidateFromDockerfile(String dockerfile) {
        if (dockerfile == null || dockerfile.isBlank()) {
            return null;
        }
        Matcher nginx = NGINX_CONF.matcher(dockerfile);
        if (nginx.find()) {
            return new Candidate(nginx.group(1), "configuration nginx copiée dans l'image");
        }
        String command = lastCommand(dockerfile);
        if (command == null) {
            return null;
        }
        Matcher m = ASGI_WSGI.matcher(command);
        if (m.find()) {
            return new Candidate(m.group(1).replace('.', '/') + ".py", "commande « " + command + " »");
        }
        m = PYTHON_FILE.matcher(command);
        if (m.find()) {
            return new Candidate(m.group(1), "commande « " + command + " »");
        }
        m = PYTHON_MODULE.matcher(command);
        if (m.find()) {
            return new Candidate(m.group(1).replace('.', '/') + ".py", "commande « " + command + " »");
        }
        m = NODE_FILE.matcher(command);
        if (m.find()) {
            return new Candidate(m.group(1), "commande « " + command + " »");
        }
        return null;
    }

    /** Dernière instruction CMD ou ENTRYPOINT, forme JSON aplatie (« uvicorn main:app --port 8000 »). */
    private static String lastCommand(String dockerfile) {
        String last = null;
        for (String raw : dockerfile.split("\n")) {
            String line = raw.trim();
            String upper = line.toUpperCase(Locale.ROOT);
            if (upper.startsWith("CMD ") || upper.startsWith("ENTRYPOINT ")) {
                String args = line.substring(line.indexOf(' ') + 1).trim();
                if (args.startsWith("[")) {
                    args = args.replaceAll("[\\[\\]\"]", "").replace(",", " ").replaceAll("\\s+", " ").trim();
                }
                last = args;
            }
        }
        return last;
    }

    private static String stripLineNumbers(String content) {
        StringBuilder sb = new StringBuilder();
        for (String line : content.split("\n")) {
            sb.append(LINE_NUMBER_PREFIX.matcher(line).replaceFirst("")).append('\n');
        }
        return sb.toString();
    }
}
