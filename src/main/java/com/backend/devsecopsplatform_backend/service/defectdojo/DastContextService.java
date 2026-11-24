package com.backend.devsecopsplatform_backend.service.defectdojo;

import com.backend.devsecopsplatform_backend.entity.application.AppService;
import com.backend.devsecopsplatform_backend.entity.application.AppServiceRole;
import com.backend.devsecopsplatform_backend.repository.application.AppServiceRepository;
import com.backend.devsecopsplatform_backend.service.remediation.SourceSnippetFetcherService;
import com.backend.devsecopsplatform_backend.service.application.AppNaming;
import com.backend.devsecopsplatform_backend.service.defectdojo.dto.DefectDojoFindingDetailResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
 *   <li>le service qui a réellement répondu, d'après le routage de l'Ingress EnviroTest
 *       (« / » → frontend, « /api » → backend…) — pas forcément le service sous lequel DefectDojo range le finding ;</li>
 *   <li>les fichiers de ce service qui produisent les réponses HTTP (Dockerfile → package.json / vite.config.ts,
 *       main.py, nginx.conf…), lus EN ENTIER, et des constats vérifiables (« aucune mention de Content-Security-Policy ») ;</li>
 *   <li>la chaîne d'exposition (Cloudflare → Ingress Traefik généré par la plateforme → conteneur).</li>
 * </ol>
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class DastContextService {

    static final String CORS_TEST_ORIGIN = "https://origine-externe.example";
    private static final Duration TIMEOUT = Duration.ofSeconds(6);
    private static final long PROBE_TTL_MS = 120_000;
    private static final long REPO_TTL_MS = 300_000;
    /** Au-delà, l'extrait envoyé à l'IA se limite aux lignes de configuration HTTP. */
    private static final int FULL_EXCERPT_MAX_LINES = 90;
    private static final int FOCUSED_EXCERPT_MAX_LINES = 70;

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

    private static final Pattern ASGI_WSGI = Pattern.compile(
            "\\b(?:uvicorn|gunicorn|hypercorn|daphne|granian)\\b.*?\\b([A-Za-z_][\\w.]*)\\s*:\\s*[A-Za-z_]\\w*");
    private static final Pattern PYTHON_FILE = Pattern.compile("\\bpython[\\d.]*\\s+(?:-u\\s+)?([\\w./-]+\\.py)\\b");
    private static final Pattern PYTHON_MODULE = Pattern.compile("\\bpython[\\d.]*\\s+-m\\s+([A-Za-z_][\\w.]*)");
    private static final Pattern NODE_FILE = Pattern.compile("\\bnode\\s+([\\w./-]+\\.(?:m?js|cjs))\\b");
    private static final Pattern NGINX_CONF = Pattern.compile("(?im)^\\s*COPY\\s+(?:--\\S+\\s+)*(\\S+\\.conf)\\s+/etc/nginx/");
    private static final Pattern PACKAGE_SCRIPT = Pattern.compile("\\b(?:npm|pnpm|yarn)\\s+(?:run\\s+)?([\\w:.-]+)");
    private static final Pattern BASE_IMAGE = Pattern.compile("(?im)^\\s*FROM\\s+(\\S+)");
    /** Lignes qui configurent les réponses HTTP (création de l'app, middlewares, en-têtes, serveur). */
    private static final Pattern CONFIG_HINT = Pattern.compile(
            "(?i)(FastAPI\\(|Flask\\(|express\\(\\)|add_middleware|@app\\.middleware|app\\.use\\(|Middleware\\b|CORS|allow_origins"
                    + "|response\\.headers|\\.headers\\s*[\\[=]|headers\\s*:|setHeader|add_header|helmet|\\bserver\\s*:\\s*\\{"
                    + "|\\bpreview\\s*:\\s*\\{|defineConfig|SecurityFilterChain|http\\.headers|Content-Security-Policy"
                    + "|X-Frame-Options|Strict-Transport|frame-ancestors|listen\\s+\\d|location\\s+/)");

    private final SourceSnippetFetcherService sourceSnippetFetcherService;
    private final AppServiceRepository appServiceRepository;
    private final ObjectMapper objectMapper;

    @Value("${deployment.ingress.custom-base-domain:}")
    private String platformDomain;

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    private final Map<String, Cached<DefectDojoFindingDetailResponse.LiveHttpCheck>> probeCache = new ConcurrentHashMap<>();
    private final Map<String, Cached<RepoFacts>> repoCache = new ConcurrentHashMap<>();

    private record Cached<T>(T value, long at) {
        boolean fresh(long ttl) {
            return System.currentTimeMillis() - at < ttl;
        }
    }

    /** Service qui a produit la réponse observée par ZAP. */
    record Responder(AppService service, String label, String reason) {}

    /**
     * Ce que la plateforme a lu dans le dépôt du service qui a répondu.
     *
     * @param filePath     fichier principal (configuration HTTP) ou null
     * @param fullNumbered fichier complet numéroté (affichage)
     * @param aiExcerpt    extrait envoyé à l'IA : fichier entier s'il est court, sinon lignes de configuration HTTP
     * @param facts        constats vérifiables, une phrase chacun
     */
    record RepoFacts(String filePath, String source, String fullNumbered, String aiExcerpt, String origin, List<String> facts) {}

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

        String url = target != null ? target : (urls.isEmpty() ? null : urls.get(0));
        Responder responder = resolveResponder(app, url, urls);
        if (responder.service() != null) {
            detail.setRespondingServiceId(responder.service().getId());
            detail.setRespondingService(responder.label());
            detail.setRoutingReason(responder.reason());
        }

        if (responder.service() != null && (detail.getCodeSnippet() == null || detail.getCodeSnippet().isBlank())) {
            AppService svc = responder.service();
            String svcBranch = Objects.equals(svc.getId(), app != null ? app.getId() : null) || svc.getGitBranch() == null
                    ? branch : svc.getGitBranch();
            RepoFacts facts = repoFacts(svc, svcBranch, targetHeaders(detail.getToolRuleId(), detail.getTitle()));
            if (facts != null) {
                detail.setRepositoryFacts(facts.facts());
                if (facts.filePath() != null) {
                    detail.setCodeSnippet(facts.fullNumbered());
                    detail.setCodeContextSource(facts.source());
                    detail.setCodeFilePath(facts.filePath());
                    detail.setCodeContextHint(facts.origin());
                    detail.setAiCodeExcerpt(facts.aiExcerpt());
                }
            }
        }
        if (target != null) {
            detail.setExposureChain(exposureChain(target, detail.getLiveCheck(), responder));
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

    /** Noms d'en-têtes / directives à rechercher dans le dépôt pour une règle ZAP. */
    static List<String> targetHeaders(String ruleId, String title) {
        String t = title == null ? "" : title.toLowerCase(Locale.ROOT);
        String id = ruleId == null ? "" : ruleId.trim();
        if (id.equals("10038") || id.equals("10055") || t.contains("content security policy") || t.contains("csp")) {
            return List.of("Content-Security-Policy");
        }
        if (id.equals("10035") || t.contains("strict-transport")) return List.of("Strict-Transport-Security");
        if (id.equals("10020") || t.contains("clickjacking")) return List.of("X-Frame-Options", "frame-ancestors");
        if (id.equals("10021") || t.contains("x-content-type")) return List.of("X-Content-Type-Options", "nosniff");
        if (id.equals("10063") || t.contains("permissions policy")) return List.of("Permissions-Policy");
        if (id.equals("90004") || t.contains("cross-origin-")) {
            return List.of("Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy");
        }
        if (id.equals("10098") || t.contains("cross-domain") || t.contains("cors")) {
            return List.of("Access-Control-Allow-Origin", "allow_origins", "cors");
        }
        if (id.equals("10036") || id.equals("10037")) return List.of("Server", "X-Powered-By");
        if (id.equals("10015") || id.equals("10049") || t.contains("cache")) return List.of("Cache-Control");
        if (t.contains("cookie")) return List.of("SameSite", "HttpOnly", "Secure");
        return List.of();
    }

    // ── Service qui a répondu ────────────────────────────────────────────────────────────────

    /**
     * Routage EnviroTest (chemins, un seul hôte) : « / » → service FRONTEND, « /api… » → l'API,
     * « /&lt;nom-du-service&gt;… » → ce service. DefectDojo range les résultats ZAP de l'application sous
     * UN service : ce n'est pas forcément celui qui a répondu.
     */
    Responder resolveResponder(AppService app, String url, List<String> allUrls) {
        if (app == null) {
            return new Responder(null, null, null);
        }
        List<AppService> services = List.of(app);
        try {
            if (app.getManagedApplication() != null && app.getManagedApplication().getId() != null) {
                List<AppService> siblings = appServiceRepository.findByManagedApplication_Id(app.getManagedApplication().getId());
                if (!siblings.isEmpty()) services = siblings;
            }
        } catch (Exception e) {
            log.debug("[DAST] Services de l'application non lus : {}", e.getMessage());
        }
        if (services.size() <= 1) {
            return new Responder(app, label(app), "service unique de l'application");
        }
        String path = pathOf(url);
        AppService front = services.stream().filter(s -> s.getRole() == AppServiceRole.FRONTEND).findFirst().orElse(null);
        AppService back = services.stream().filter(s -> s.getRole() == AppServiceRole.BACKEND).findFirst().orElse(null);
        if (front != null && back != null && (path.equals("/api") || path.startsWith("/api/"))) {
            return new Responder(back, label(back), "chemin « " + path + " » routé vers l'API par l'Ingress EnviroTest");
        }
        for (AppService s : services) {
            if (s == front) continue;
            String prefix = "/" + AppNaming.k8sName(s.getName());
            if (path.equals(prefix) || path.startsWith(prefix + "/")) {
                return new Responder(s, label(s), "chemin « " + prefix + "… » routé vers ce service par l'Ingress EnviroTest");
            }
        }
        AppService primary = front != null ? front : app;
        String paths = allUrls == null ? path : String.join(", ", allUrls.stream().map(DastContextService::pathOf).distinct().toList());
        return new Responder(primary, label(primary), "chemins « " + paths + " » servis par le service principal"
                + (front != null ? " (FRONTEND)" : "") + " selon le routage de l'Ingress EnviroTest");
    }

    private static String pathOf(String url) {
        if (url == null) return "/";
        try {
            String p = URI.create(url.trim()).getPath();
            return p == null || p.isBlank() ? "/" : p;
        } catch (Exception e) {
            return "/";
        }
    }

    private static String label(AppService s) {
        String role = s.getRole() != null ? " (" + s.getRole().name() + ")" : "";
        String repo = repoShort(s.getGitRepositoryUrl());
        return s.getName() + role + (repo.isEmpty() ? "" : " — dépôt " + repo);
    }

    private static String repoShort(String url) {
        if (url == null) return "";
        String u = url.trim().replaceFirst("\\.git$", "");
        int i = u.indexOf("github.com/");
        if (i >= 0) return u.substring(i + "github.com/".length());
        i = u.indexOf("gitlab.com/");
        if (i >= 0) return u.substring(i + "gitlab.com/".length());
        return u;
    }

    // ── Chaîne d'exposition ───────────────────────────────────────────────────────────────────

    private List<String> exposureChain(String url, DefectDojoFindingDetailResponse.LiveHttpCheck check, Responder responder) {
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
        chain.add(responder.service() != null
                ? "Conteneur du service " + responder.label() + " : " + responder.reason() + "."
                : "Conteneur de l'application.");
        return chain;
    }

    // ── Dépôt du service qui a répondu ───────────────────────────────────────────────────────

    RepoFacts repoFacts(AppService service, String branch, List<String> targets) {
        String key = service.getId() + "|" + branch + "|" + String.join(",", targets);
        Cached<RepoFacts> hit = repoCache.get(key);
        if (hit != null && hit.fresh(REPO_TTL_MS)) {
            return hit.value();
        }
        RepoFacts facts;
        try {
            facts = readRepoFacts(service, branch, targets);
        } catch (Exception e) {
            log.debug("[DAST] Lecture du dépôt {} impossible : {}", service.getId(), e.getMessage());
            facts = null;
        }
        repoCache.put(key, new Cached<>(facts, System.currentTimeMillis()));
        return facts;
    }

    private RepoFacts readRepoFacts(AppService service, String branch, List<String> targets) {
        String source = service.getGitRepositoryUrl() != null && service.getGitRepositoryUrl().contains("github")
                ? "GITHUB" : "GITLAB";
        String dockerPath = service.getDockerfilePath() == null || service.getDockerfilePath().isBlank()
                ? "Dockerfile" : service.getDockerfilePath().trim();
        Optional<String> dockerfile = sourceSnippetFetcherService.tryFetchFullFile(service, branch, dockerPath);
        if (dockerfile.isEmpty() && !"Dockerfile".equals(dockerPath)) {
            dockerPath = "Dockerfile";
            dockerfile = sourceSnippetFetcherService.tryFetchFullFile(service, branch, dockerPath);
        }
        List<String> facts = new ArrayList<>();
        if (dockerfile.isEmpty()) {
            facts.add("Dockerfile du service « " + service.getName() + " » non lu : fichier produisant les réponses HTTP inconnu.");
            return new RepoFacts(null, source, null, null, null, facts);
        }
        String docker = dockerfile.get();
        String dockerDir = dockerPath.contains("/") ? dockerPath.substring(0, dockerPath.lastIndexOf('/') + 1) : "";
        String command = lastCommand(docker);
        Matcher base = BASE_IMAGE.matcher(docker);
        String baseImage = null;
        while (base.find()) baseImage = base.group(1);
        facts.add(dockerPath + " : image " + (baseImage != null ? baseImage : "?") + ", démarrage "
                + (command != null ? "« " + command + " »" : "non défini (pas de CMD/ENTRYPOINT)") + ".");

        List<String> candidates = new ArrayList<>();
        String origin = "déduit de " + dockerPath;
        Candidate c = candidateFromDockerfile(docker);
        if (c != null) {
            candidates.add(c.path());
            origin += " : " + c.evidence();
        }
        if (command != null && (PACKAGE_SCRIPT.matcher(command).find() || command.matches(".*\\b(vite|next|react-scripts)\\b.*"))) {
            origin = nodeFacts(service, branch, dockerDir, dockerPath, command, facts, candidates);
        }

        for (String candidate : candidates) {
            for (String path : dockerDir.isEmpty() ? List.of(candidate) : List.of(dockerDir + candidate, candidate)) {
                Optional<String> content = sourceSnippetFetcherService.tryFetchFullFile(service, branch, path);
                if (content.isPresent()) {
                    addFileFacts(path, content.get(), targets, facts);
                    return new RepoFacts(path, source, SourceSnippetFetcherService.numberLines(content.get(), 400),
                            aiExcerpt(content.get()), origin, facts);
                }
            }
        }
        // Aucun fichier de configuration identifié : le Dockerfile reste la meilleure preuve disponible.
        if (!candidates.isEmpty()) {
            facts.add("Fichier attendu non trouvé dans le dépôt : " + String.join(", ", candidates) + ".");
        }
        addFileFacts(dockerPath, docker, targets, facts);
        return new RepoFacts(dockerPath, source, SourceSnippetFetcherService.numberLines(docker, 400),
                aiExcerpt(docker), "Dockerfile du service", facts);
    }

    /** Service Node : script réellement lancé, type de serveur, fichier de configuration à lire. */
    private String nodeFacts(AppService service, String branch, String dockerDir, String dockerPath, String command,
                             List<String> facts, List<String> candidates) {
        String origin = "déduit de " + dockerPath + " et package.json";
        String scriptName = null;
        Matcher sm = PACKAGE_SCRIPT.matcher(command);
        if (sm.find()) {
            scriptName = sm.group(1);
            if ("install".equals(scriptName) || "ci".equals(scriptName)) scriptName = null;
        }
        String scriptCmd = command;
        Optional<String> pkg = sourceSnippetFetcherService.tryFetchFullFile(service, branch, dockerDir + "package.json");
        if (pkg.isEmpty() && !dockerDir.isEmpty()) {
            pkg = sourceSnippetFetcherService.tryFetchFullFile(service, branch, "package.json");
        }
        if (pkg.isPresent()) {
            try {
                JsonNode root = objectMapper.readTree(pkg.get());
                if (scriptName != null && root.path("scripts").has(scriptName)) {
                    scriptCmd = root.path("scripts").path(scriptName).asText();
                    facts.add("package.json : script « " + scriptName + " » = « " + scriptCmd + " ».");
                }
                List<String> deps = new ArrayList<>();
                root.path("dependencies").fieldNames().forEachRemaining(deps::add);
                if (!deps.isEmpty()) {
                    facts.add("package.json : dépendances " + String.join(", ", deps.subList(0, Math.min(deps.size(), 12)))
                            + (deps.size() > 12 ? "…" : "") + ".");
                    List<String> external = externalServices(deps);
                    if (!external.isEmpty()) {
                        facts.add("Services externes appelés par le navigateur (d'après les dépendances) : "
                                + String.join(" ; ", external) + " — une CSP doit les autoriser.");
                    }
                }
            } catch (Exception e) {
                log.debug("[DAST] package.json illisible : {}", e.getMessage());
            }
        }
        String s = scriptCmd.toLowerCase(Locale.ROOT);
        if (s.matches(".*\\bvite\\b.*") && !s.contains("vite build")) {
            boolean preview = s.contains("preview");
            facts.add(preview
                    ? "Le service est servi par « vite preview » (serveur de prévisualisation, non destiné à la production) ; "
                    + "ses en-têtes se règlent dans preview.headers de vite.config."
                    : "Le service est servi par le serveur de DÉVELOPPEMENT Vite (« vite ») : il n'est pas destiné à la production. "
                    + "Ses en-têtes peuvent être posés avec server.headers dans vite.config (développement uniquement) ; "
                    + "en production, le build statique (vite build) est servi par un serveur web (nginx…) qui pose les en-têtes.");
            candidates.add("vite.config.ts");
            candidates.add("vite.config.js");
            candidates.add("vite.config.mjs");
        } else if (s.matches(".*\\bnext\\b.*")) {
            facts.add("Le service est une application Next.js (« " + scriptCmd + " »).");
            candidates.add("next.config.js");
            candidates.add("next.config.mjs");
            candidates.add("next.config.ts");
        } else if (s.contains("react-scripts start")) {
            facts.add("Le service est servi par le serveur de DÉVELOPPEMENT Create React App : non destiné à la production.");
        } else {
            Matcher nf = NODE_FILE.matcher(scriptCmd);
            if (nf.find()) candidates.add(nf.group(1));
        }
        return origin;
    }

    /** SDK front connus → domaines que le navigateur contacte (utile pour une CSP qui ne casse rien). */
    private static final Map<String, String> KNOWN_BROWSER_SDKS = Map.of(
            "@supabase/supabase-js", "API Supabase (https://<projet>.supabase.co, connect-src ; wss:// pour le temps réel)",
            "firebase", "Firebase (*.googleapis.com, *.firebaseio.com, connect-src)",
            "@stripe/stripe-js", "Stripe (js.stripe.com en script-src et frame-src)",
            "@sentry/react", "Sentry (*.ingest.sentry.io, connect-src)",
            "@sentry/browser", "Sentry (*.ingest.sentry.io, connect-src)",
            "mapbox-gl", "Mapbox (api.mapbox.com, connect-src et img-src)",
            "@auth0/auth0-react", "Auth0 (<tenant>.auth0.com, connect-src et frame-src)");

    static List<String> externalServices(List<String> deps) {
        List<String> out = new ArrayList<>();
        for (String d : deps) {
            String service = KNOWN_BROWSER_SDKS.get(d);
            if (service != null) out.add(service);
        }
        return out;
    }

    /** Constats vérifiables sur un fichier lu en entier. */
    private static void addFileFacts(String path, String content, List<String> targets, List<String> facts) {
        String[] lines = content.split("\r\n|\n|\r", -1);
        for (String target : targets) {
            List<Integer> hits = new ArrayList<>();
            String t = target.toLowerCase(Locale.ROOT);
            for (int i = 0; i < lines.length; i++) {
                if (lines[i].toLowerCase(Locale.ROOT).contains(t)) hits.add(i + 1);
            }
            facts.add(hits.isEmpty()
                    ? path + " (" + lines.length + " lignes, lu en entier) : aucune mention de « " + target + " »."
                    : path + " : « " + target + " » mentionné ligne" + (hits.size() > 1 ? "s " : " ")
                    + hits.stream().limit(5).map(String::valueOf).reduce((a, b) -> a + ", " + b).orElse("") + ".");
        }
        List<String> config = new ArrayList<>();
        for (int i = 0; i < lines.length && config.size() < 6; i++) {
            Matcher m = CONFIG_HINT.matcher(lines[i]);
            if (m.find()) {
                String s = lines[i].trim().replaceAll("\\s+", " ");
                config.add(s.substring(0, Math.min(s.length(), 60)) + " (l. " + (i + 1) + ")");
            }
        }
        facts.add(config.isEmpty()
                ? path + " : aucune configuration HTTP (middleware, en-têtes, serveur) repérée."
                : path + " : configuration HTTP repérée — " + String.join(" ; ", config) + ".");
    }

    /** Fichier court : entier. Fichier long : seulement les lignes de configuration HTTP (± 2 lignes). */
    static String aiExcerpt(String content) {
        String[] lines = content.split("\r\n|\n|\r", -1);
        if (lines.length <= FULL_EXCERPT_MAX_LINES) {
            return SourceSnippetFetcherService.numberLines(content, FULL_EXCERPT_MAX_LINES);
        }
        boolean[] keep = new boolean[lines.length];
        for (int i = 0; i < lines.length; i++) {
            if (CONFIG_HINT.matcher(lines[i]).find()) {
                for (int j = Math.max(0, i - 2); j <= Math.min(lines.length - 1, i + 2); j++) keep[j] = true;
            }
        }
        StringBuilder sb = new StringBuilder();
        int kept = 0;
        boolean gap = false;
        for (int i = 0; i < lines.length && kept < FOCUSED_EXCERPT_MAX_LINES; i++) {
            if (!keep[i]) {
                gap = true;
                continue;
            }
            if (gap && kept > 0) sb.append("   ...|\n");
            gap = false;
            sb.append(String.format("%5d| %s%n", i + 1, lines[i]));
            kept++;
        }
        if (kept == 0) {
            return SourceSnippetFetcherService.numberLines(content, 40);
        }
        return "(extrait ciblé : lignes de configuration HTTP seulement ; le reste du fichier — routes, accès aux données — "
                + "ne concerne pas ce finding)\n" + sb;
    }

    // ── Point d'entrée déduit du Dockerfile ───────────────────────────────────────────────────

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
    static String lastCommand(String dockerfile) {
        String last = null;
        for (String raw : dockerfile.split("\n")) {
            String line = raw.replaceFirst("^\\s*\\d+\\| ?", "").trim();
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
}
