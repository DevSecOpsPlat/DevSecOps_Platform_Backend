package com.backend.devsecopsplatform_backend.service;

import com.backend.devsecopsplatform_backend.service.application.ApplicationService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.gitlab4j.api.GitLabApi;
import org.gitlab4j.api.GitLabApiException;
import org.gitlab4j.api.models.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Service pour interagir avec GitLab API
 * Gère les pipelines, jobs, artifacts et rapports de sécurité
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class GitLabService {

    private final GitLabApi gitLabApi;
    private final ObjectMapper objectMapper;
    private final ApplicationService applicationService;
    private final RestTemplate sonarRestTemplate;
    private final TranslationService translationService;

    @Value("${gitlab.project-id}")
    private Long gitlabProjectId;

    @Value("${gitlab.api-url}")
    private String gitlabApiUrl;

    @Value("${gitlab.token}")
    private String gitlabToken;

    @Value("${pipeline.default-branch}")
    private String defaultBranch;
    @Value("${gitlab.timeout.seconds:3}")
    private int gitlabTimeoutSeconds;

    @Value("${gitlab.max-pipelines:20}")
    private int maxPipelines;

    @Value("${pipeline.timeout-minutes}")
    private Integer timeoutMinutes;

    // SonarQube / SonarCloud
    @Value("${sonarqube.host-url}")
    private String sonarHostUrl;

    @Value("${sonarqube.token}")
    private String sonarToken;

    @Value("${sonarqube.project-key}")
    private String sonarProjectKey;

    /**
     * Utilisateur SonarCloud par défaut pour \"Assign to me\" côté plateforme.
     * (par exemple le mainteneur principal du projet).
     */
    @Value("${sonarqube.default-assignee:}")
    private String sonarDefaultAssignee;

    @Value("${sonarqube.accept-language:fr}")
    private String sonarAcceptLanguage;

    // ============================================
    // PIPELINE - CRÉATION ET DÉCLENCHEMENT
    // ============================================

    /**
     * Déclenche un pipeline GitLab avec toutes les variables nécessaires.
     * Ordre d'exécution côté .gitlab-ci.yml : Clone (GITHUB_TOKEN) → Scan (Trivy/SonarQube) → Report (artefact .json).
     *
     * @param gitRepoUrl     URL du repository GitHub
     * @param branch        Branche à builder
     * @param envId         ID de l'environnement (UUID)
     * @param applicationId ID de l'application (pour récupérer le token GitHub)
     * @param dockerfilePath Chemin du Dockerfile dans le repo (ex: ./Dockerfile)
     * @return Pipeline créé
     */
    /**
     * Lance un pipeline sur le projet GitLab amanibennaceur-group/EnviroTest (branche master).
     * Le .gitlab-ci.yml existe déjà ; le backend envoie uniquement les variables (GIT_REPO_URL, GIT_BRANCH, GITHUB_TOKEN, etc.).
     * Utilise RestTemplate pour respecter le format exact de l'API GitLab (variables en tableau).
     */
    public Pipeline triggerPipeline(
            String gitRepoUrl,
            String branch,
            String envId,
            UUID applicationId,
            String dockerfilePath,
            Integer ttlHours,
            String namespace
    ) {
        try {
            String githubToken = applicationService.getDecryptedGithubToken(applicationId);
            String gitBranch = branch != null && !branch.isBlank() ? branch : "main";
            String dockerPath = dockerfilePath != null && !dockerfilePath.isBlank() ? dockerfilePath : "./Dockerfile";
            int ttl = (ttlHours != null && ttlHours > 0) ? ttlHours : 4;
            String ns = namespace != null ? namespace : "";

            log.info("📋 [Pipeline] Données envoyées au pipeline GitLab (amanibennaceur-group/EnviroTest, ref=master):");
            log.info("   GIT_REPO_URL={}", gitRepoUrl);
            log.info("   GIT_BRANCH={}", gitBranch);
            log.info("   ENVIRONMENT_ID={}", envId);
            log.info("   DOCKERFILE_PATH={}", dockerPath);
            log.info("   TTL_HOURS={}", ttl);
            log.info("   K8S_NAMESPACE={}", ns);
            log.info("   GITHUB_TOKEN présent={}", githubToken != null && !githubToken.isEmpty());

            if (githubToken == null || githubToken.isEmpty()) {
                log.warn("⚠️ Pas de token GitHub configuré pour l'application {}", applicationId);
            } else {
                log.info("🔐 Token GitHub récupéré et déchiffré avec succès");
            }

            // Ref = branche du projet GitLab où se trouve le .gitlab-ci.yml (master pour EnviroTest)
            String ref = defaultBranch;
            log.info("   GitLab ref={} (branche du projet template)", ref);

            // Variables au format attendu par l'API GitLab : tableau de { key, value }
            List<Map<String, String>> variablesList = new ArrayList<>();
            addVar(variablesList, "GIT_REPO_URL", gitRepoUrl);
            addVar(variablesList, "GIT_BRANCH", gitBranch);
            addVar(variablesList, "GITHUB_TOKEN", githubToken != null ? githubToken : "");
            addVar(variablesList, "ENVIRONMENT_ID", envId);
            addVar(variablesList, "DOCKERFILE_PATH", dockerPath);
            addVar(variablesList, "TTL_HOURS", String.valueOf(ttl));
            addVar(variablesList, "K8S_NAMESPACE", ns);
            addVar(variablesList, "SKIP_DEPLOYMENT", "true");

            Map<String, Object> body = new HashMap<>();
            body.put("ref", ref);
            body.put("variables", variablesList);

            String url = gitlabApiUrl + "/projects/" + gitlabProjectId + "/pipeline";
            RestTemplate rest = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(org.springframework.http.MediaType.APPLICATION_JSON);
            headers.set("PRIVATE-TOKEN", gitlabToken);

            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);
            ResponseEntity<Map> response = rest.exchange(url, HttpMethod.POST, entity, Map.class);

            if (response.getStatusCode() != HttpStatus.OK && response.getStatusCode() != HttpStatus.CREATED) {
                throw new RuntimeException("GitLab API a répondu: " + response.getStatusCode());
            }
            Map<String, Object> res = response.getBody();
            if (res == null) {
                throw new RuntimeException("Réponse GitLab vide");
            }

            Pipeline pipeline = mapToPipeline(res);
            log.info("✅ Pipeline lancé - ID: {} - URL: {}", pipeline.getId(), pipeline.getWebUrl());
            return pipeline;

        } catch (Exception e) {
            if (e instanceof RuntimeException && e.getCause() != null) {
                log.error("❌ Erreur déclenchement pipeline: {} - Cause: {}", e.getMessage(), e.getCause().getMessage());
            } else {
                log.error("❌ Erreur déclenchement pipeline: {}", e.getMessage());
            }
            throw new RuntimeException("Impossible de lancer le pipeline: " + e.getMessage(), e);
        }
    }

    private void addVar(List<Map<String, String>> list, String key, String value) {
        Map<String, String> entry = new HashMap<>();
        entry.put("key", key);
        entry.put("value", value != null ? value : "");
        list.add(entry);
    }

    @SuppressWarnings("unchecked")
    private Pipeline mapToPipeline(Map<String, Object> res) {
        Pipeline p = new Pipeline();
        if (res.get("id") instanceof Number) {
            p.setId(((Number) res.get("id")).longValue());
        }
        if (res.get("web_url") != null) {
            p.setWebUrl((String) res.get("web_url"));
        }
        if (res.get("status") != null) {
            try {
                p.setStatus(PipelineStatus.valueOf(((String) res.get("status")).toUpperCase()));
            } catch (Exception ignored) {
                p.setStatus(PipelineStatus.PENDING);
            }
        }
        if (res.get("ref") != null) {
            p.setRef((String) res.get("ref"));
        }
        return p;
    }

    // ============================================
    // PIPELINE - STATUT ET INFORMATIONS
    // ============================================

    /**
     * Récupère le statut d'un pipeline
     *
     * @param pipelineId ID du pipeline
     * @return Statut du pipeline (PENDING, RUNNING, SUCCESS, FAILED, etc.)
     */
    public PipelineStatus getPipelineStatus(Long pipelineId) {
        try {
            Pipeline pipeline = gitLabApi.getPipelineApi()
                    .getPipeline(gitlabProjectId, pipelineId);

            log.info("📊 Pipeline {} - Statut: {}", pipelineId, pipeline.getStatus());
            return pipeline.getStatus();

        } catch (GitLabApiException e) {
            log.error("❌ Erreur récupération statut pipeline {}: {}", pipelineId, e.getMessage());
            throw new RuntimeException("Impossible de récupérer le statut du pipeline", e);
        }
    }

    /**
     * Récupère les informations complètes d'un pipeline
     *
     * @param pipelineId ID du pipeline
     * @return Pipeline complet
     */
    public Pipeline getPipeline(Long pipelineId) {
        try {
            Pipeline pipeline = gitLabApi.getPipelineApi()
                    .getPipeline(gitlabProjectId, pipelineId);

            log.info("📋 Pipeline {} récupéré - Statut: {} - Durée: {}s",
                    pipelineId, pipeline.getStatus(), pipeline.getDuration());
            return pipeline;

        } catch (GitLabApiException e) {
            log.error("❌ Erreur récupération pipeline {}: {}", pipelineId, e.getMessage());
            throw new RuntimeException("Pipeline non trouvé", e);
        }
    }

    /**
     * Vérifie si un pipeline est terminé
     *
     * @param pipelineId ID du pipeline
     * @return true si le pipeline est terminé (SUCCESS, FAILED, CANCELED)
     */
    public boolean isPipelineFinished(Long pipelineId) {
        PipelineStatus status = getPipelineStatus(pipelineId);
        boolean isFinished = status == PipelineStatus.SUCCESS ||
                status == PipelineStatus.FAILED ||
                status == PipelineStatus.CANCELED ||
                status == PipelineStatus.SKIPPED;

        if (isFinished) {
            log.info("✅ Pipeline {} est terminé avec statut: {}", pipelineId, status);
        }

        return isFinished;
    }

    /**
     * Vérifie si un pipeline a réussi
     */
    public boolean isPipelineSuccessful(Long pipelineId) {
        return getPipelineStatus(pipelineId) == PipelineStatus.SUCCESS;
    }

    // ============================================
    // JOBS - RÉCUPÉRATION ET LOGS
    // ============================================

    /**
     * Récupère tous les jobs d'un pipeline
     *
     * @param pipelineId ID du pipeline
     * @return Liste des jobs
     */
    public List<Job> getPipelineJobs(Long pipelineId) {
        try {
            List<Job> jobs = gitLabApi.getJobApi()
                    .getJobsForPipeline(gitlabProjectId, pipelineId);

            log.info("📋 Pipeline {} - {} jobs trouvés", pipelineId, jobs.size());

            // Log le statut de chaque job
            for (Job job : jobs) {
                log.debug("  → Job: {} ({})", job.getName(), job.getStatus());
            }

            return jobs;

        } catch (GitLabApiException e) {
            log.error("❌ Erreur récupération jobs du pipeline {}: {}", pipelineId, e.getMessage());
            throw new RuntimeException("Impossible de récupérer les jobs", e);
        }
    }

    /**
     * Récupère un job spécifique par son ID
     *
     * @param jobId ID du job
     * @return Job
     */
    public Job getJob(Long jobId) {
        try {
            Job job = gitLabApi.getJobApi().getJob(gitlabProjectId, jobId);

            log.info("🔍 Job {} récupéré - Nom: {} - Statut: {}",
                    jobId, job.getName(), job.getStatus());
            return job;

        } catch (GitLabApiException e) {
            log.error("❌ Erreur récupération job {}: {}", jobId, e.getMessage());
            throw new RuntimeException("Job non trouvé", e);
        }
    }

    /**
     * Récupère les logs d'un job
     *
     * @param jobId ID du job
     * @return Logs du job (texte brut)
     */
    public String getJobLogs(Long jobId) {
        try {
            String logs = gitLabApi.getJobApi()
                    .getTrace(gitlabProjectId, jobId);

            log.info("📝 Logs du job {} récupérés ({} caractères)", jobId, logs.length());
            return logs;

        } catch (GitLabApiException e) {
            log.error("❌ Erreur récupération logs job {}: {}", jobId, e.getMessage());
            return "Logs non disponibles: " + e.getMessage();
        }
    }

    /**
     * Récupère un job par son nom (ex: "sast-sonarqube", "dependency-scan-trivy").
     * Comparaison insensible à la casse ; plusieurs tentatives GitLab avec le même nom :
     * on privilégie le dernier job en SUCCESS, sinon le dernier par id (message d’erreur cohérente).
     *
     * @param pipelineId ID du pipeline
     * @param jobName Nom du job
     * @return Job trouvé ou null
     */
    public Job getJobByName(Long pipelineId, String jobName) {
        List<Job> jobs = getPipelineJobs(pipelineId);
        if (jobName == null || jobName.isBlank()) {
            return null;
        }
        String needle = jobName.trim();
        List<Job> matches = jobs.stream()
                .filter(job -> job.getName() != null && job.getName().trim().equalsIgnoreCase(needle))
                .toList();
        if (matches.isEmpty()) {
            String norm = normalizePipelineJobName(needle);
            matches = jobs.stream()
                    .filter(job -> job.getName() != null
                            && normalizePipelineJobName(job.getName()).equals(norm))
                    .toList();
        }
        if (matches.isEmpty()) {
            return null;
        }
        Optional<Job> latestSuccess = matches.stream()
                .filter(j -> j.getStatus() == JobStatus.SUCCESS)
                .max(Comparator.comparing(Job::getId, Comparator.nullsLast(Long::compareTo)));
        if (latestSuccess.isPresent()) {
            return latestSuccess.get();
        }
        return matches.stream()
                .max(Comparator.comparing(Job::getId, Comparator.nullsLast(Long::compareTo)))
                .orElse(null);
    }

    private static String normalizePipelineJobName(String name) {
        return name.trim().toLowerCase(Locale.ROOT).replace('_', '-');
    }

    // ============================================
    // ARTIFACTS - TÉLÉCHARGEMENT ET PARSING
    // ============================================

    /**
     * Télécharge un artifact spécifique d'un job GitLab
     *
     * @param jobId ID du job qui a généré l'artifact
     * @param artifactPath Chemin relatif de l'artifact (ex: "user-repo/trivy-report.json")
     * @return InputStream contenant les données du fichier
     */
    public InputStream downloadJobArtifact(Long jobId, String artifactPath) {
        try {
            log.info("⬇️ Téléchargement artifact via RestTemplate: {} du job: {}", artifactPath, jobId);

            // 1. Construction de l'URL manuelle (API GitLab V4)
            // Format: https://gitlab.com/api/v4/projects/{id}/jobs/{job_id}/artifacts/{path}
            String url = String.format("%s/projects/%d/jobs/%d/artifacts/%s",
                    gitlabApiUrl, gitlabProjectId, jobId, artifactPath);

            // 2. Configuration des headers avec ton token privé
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.set("PRIVATE-TOKEN", gitlabToken); // Utilise ton token d'application.properties

            HttpEntity<String> entity = new HttpEntity<>(headers);

            // 3. Appel de l'API
            ResponseEntity<byte[]> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    entity,
                    byte[].class
            );

            // 4. Vérification et conversion en InputStream
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                log.info("✅ Artifact récupéré avec succès (Taille: {} octets)", response.getBody().length);
                return new ByteArrayInputStream(response.getBody());
            } else {
                log.error("❌ Échec du téléchargement. Status: {}", response.getStatusCode());
                throw new RuntimeException("Impossible de télécharger l'artifact : " + response.getStatusCode());
            }

        } catch (Exception e) {
            log.error("❌ Erreur technique lors du téléchargement de l'artifact : {}", e.getMessage());
            throw new RuntimeException("Erreur lors de la récupération du rapport de sécurité", e);
        }
    }

    public InputStream downloadAllJobArtifacts(Long jobId) {
        try {
            log.info("⬇️ Téléchargement de tous les artifacts du job: {}", jobId);

            InputStream artifactsZip = gitLabApi.getJobApi()
                    .downloadArtifactsFile(gitlabProjectId, jobId);

            log.info("✅ Tous les artifacts téléchargés (ZIP)");
            return artifactsZip;

        } catch (GitLabApiException e) {
            log.error("❌ Erreur téléchargement artifacts du job {}: {}", jobId, e.getMessage());
            throw new RuntimeException("Impossible de télécharger les artifacts", e);
        }
    }

    /**
     * Parse un rapport JSON (SonarQube, Trivy, etc.)
     *
     * @param reportStream InputStream du rapport
     * @return JsonNode parsé
     */
    public JsonNode parseSecurityReport(InputStream reportStream) {
        try {
            JsonNode report = objectMapper.readTree(reportStream);
            log.info("✅ Rapport de sécurité parsé avec succès");

            // Log quelques infos du rapport si disponible
            if (report.has("vulnerabilities")) {
                int vulnCount = report.get("vulnerabilities").size();
                log.info("📊 Rapport contient {} vulnérabilités", vulnCount);
            }

            return report;

        } catch (Exception e) {
            log.error("❌ Erreur parsing rapport JSON: {}", e.getMessage());
            throw new RuntimeException("Impossible de parser le rapport de sécurité", e);
        }
    }

    /**
     * Récupère et parse un rapport de sécurité d'un job
     *
     * @param jobId ID du job
     * @param reportFileName Nom du fichier rapport (ex: "trivy-dependencies-report.json")
     * @return JsonNode du rapport parsé
     */
    public JsonNode getSecurityReport(Long jobId, String reportFileName) {
        try {
            log.info("📊 Récupération rapport de sécurité: {} du job: {}", reportFileName, jobId);

            // Télécharger l'artifact
            InputStream reportStream = downloadJobArtifact(jobId, reportFileName);

            // Parser le JSON
            JsonNode report = parseSecurityReport(reportStream);

            log.info("✅ Rapport de sécurité récupéré et parsé");
            return report;

        } catch (Exception e) {
            log.error("❌ Erreur récupération rapport {}: {}", reportFileName, e.getMessage());
            throw new RuntimeException("Impossible de récupérer le rapport de sécurité", e);
        }
    }

    /**
     * Récupère le résultat du scan (JSON) d'un job une fois le pipeline terminé.
     * 1) Essaie quelques chemins d'artefacts connus en accès direct (rapide).
     * 2) Si rien n'est trouvé, télécharge le ZIP d'artifacts du job et cherche
     *    un fichier .json à l'intérieur (peu importe le dossier).
     *
     * @param jobId ID du job GitLab (ex: job de stage Scan)
     * @return Rapport de scan en JSON (JsonNode), ou null si aucun artefact trouvé
     */
    public JsonNode getScanResults(Long jobId) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set("PRIVATE-TOKEN", gitlabToken);

        // Chemins d'artefacts courants selon .gitlab-ci.yml (Trivy, SonarQube, rapports GitLab natifs)
        String[] artifactPaths = {
                "report.json",
                "trivy-report.json",
                "trivy-dependencies-report.json",
                "gl-dependency-scanning-report.json",
                "gl-sast-report.json",
                "sonarqube-report.json",
                "scan-report.json",
                // Variantes quand le projet est empaqueté dans un sous-répertoire (ex: user-repo/)
                "user-repo/report.json",
                "user-repo/trivy-report.json",
                "user-repo/trivy-dependencies-report.json",
                "user-repo/scan-report.json"
        };

        for (String path : artifactPaths) {
            try {
                String url = String.format("%s/projects/%d/jobs/%d/artifacts/%s",
                        gitlabApiUrl, gitlabProjectId, jobId, path);
                ResponseEntity<byte[]> response = restTemplate.exchange(
                        url,
                        HttpMethod.GET,
                        new HttpEntity<>(headers),
                        byte[].class
                );
                if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null && response.getBody().length > 0) {
                    JsonNode report = objectMapper.readTree(response.getBody());
                    log.info("✅ Scan results récupérés pour job {} (artefact direct: {})", jobId, path);
                    return report;
                }
            } catch (Exception e) {
                log.debug("Artefact direct {} non trouvé pour job {}: {}", path, jobId, e.getMessage());
            }
        }

        // Fallback générique : télécharger le ZIP de tous les artifacts et chercher un .json
        try (InputStream zipStream = gitLabApi.getJobApi().downloadArtifactsFile(gitlabProjectId, jobId);
             ZipInputStream zis = new ZipInputStream(zipStream)) {

            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();
                if (entry.isDirectory()) {
                    continue;
                }
                // On cherche un JSON de scan : d'abord ceux contenant des mots-clés, sinon le premier .json
                if (name.toLowerCase().endsWith(".json")) {
                    boolean looksLikeScan =
                            name.contains("trivy") ||
                                    name.contains("sast") ||
                                    name.contains("scan") ||
                                    name.contains("report") ||
                                    name.contains("sonar");

                    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                    byte[] tmp = new byte[4096];
                    int read;
                    while ((read = zis.read(tmp)) != -1) {
                        buffer.write(tmp, 0, read);
                    }

                    if (looksLikeScan) {
                        JsonNode report = objectMapper.readTree(buffer.toByteArray());
                        log.info("✅ Scan results récupérés pour job {} depuis le ZIP (fichier: {})", jobId, name);
                        return report;
                    } else if (log.isDebugEnabled()) {
                        log.debug("JSON trouvé dans les artifacts mais ignoré (nom: {})", name);
                    }
                }
            }
        } catch (GitLabApiException e) {
            log.warn("⚠️ Impossible de télécharger le ZIP d'artifacts pour le job {}: {}", jobId, e.getMessage());
        } catch (Exception e) {
            log.error("❌ Erreur lors de l'analyse du ZIP d'artifacts pour le job {}: {}", jobId, e.getMessage());
        }

        log.warn("⚠️ Aucun artefact JSON de scan trouvé pour le job {}", jobId);
        return null;
    }

    // ============================================
    // SONARQUBE - RÉCUPÉRATION DES RÉSULTATS
    // ============================================

    /**
     * Normalise le statut Quality Gate renvoyé par SonarQube pour un affichage frontend cohérent
     * et ajoute un message de détail (errorDescription) pour chaque condition en échec.
     */
    private Map<String, Object> normalizeQualityGateStatus(JsonNode projectStatus) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (projectStatus == null || projectStatus.isMissingNode()) return out;

        String status = projectStatus.has("status") ? projectStatus.get("status").asText("UNKNOWN")
                : (projectStatus.has("level") ? projectStatus.get("level").asText("UNKNOWN") : "UNKNOWN");
        out.put("status", status);

        JsonNode conditionsNode = projectStatus.path("conditions");
        if (!conditionsNode.isArray()) {
            out.put("conditions", Collections.emptyList());
            return out;
        }

        List<Map<String, Object>> conditions = new ArrayList<>();
        for (JsonNode cond : conditionsNode) {
            Map<String, Object> c = new LinkedHashMap<>();
            String condStatus = cond.has("status") ? cond.get("status").asText("OK")
                    : (cond.has("level") ? cond.get("level").asText("OK") : "OK");
            String metricKey = cond.has("metricKey") ? cond.get("metricKey").asText("")
                    : (cond.has("metric") ? cond.get("metric").asText("") : "");
            String actual = cond.has("actualValue") ? cond.get("actualValue").asText("0")
                    : (cond.has("actual") ? cond.get("actual").asText("0") : "0");
            String errorThreshold = cond.has("errorThreshold") ? cond.get("errorThreshold").asText("")
                    : (cond.has("error") ? cond.get("error").asText("") : "");
            String comparator = cond.has("comparator") ? cond.get("comparator").asText("")
                    : (cond.has("op") ? cond.get("op").asText("") : "");

            c.put("status", condStatus);
            c.put("metricKey", metricKey);
            c.put("metric", metricKey);
            c.put("actualValue", actual);
            c.put("errorThreshold", errorThreshold);
            c.put("comparator", comparator);
            c.put("metricLabel", frenchQualityGateMetricLabel(metricKey));

            if ("ERROR".equalsIgnoreCase(condStatus) && (actual != null || errorThreshold != null)) {
                String desc = buildQualityGateConditionErrorDescription(
                        metricKey, actual, errorThreshold, comparator);
                if (desc != null) c.put("errorDescription", desc);
            }
            conditions.add(c);
        }
        out.put("conditions", conditions);
        return out;
    }

    /**
     * SonarQube encode les notes A–E comme 1–5 dans l’API project_status ; on les affiche en lettres dans les messages.
     */
    private String formatSonarRatingForMessage(String metricKey, String raw) {
        if (raw == null || metricKey == null) {
            return raw != null ? raw : "0";
        }
        String k = metricKey.toLowerCase();
        if (!k.contains("reliability_rating") && !k.contains("security_rating")
                && !k.contains("maintainability_rating") && !k.contains("sqale_rating")) {
            return raw;
        }
        try {
            int n = Integer.parseInt(raw.trim());
            if (n >= 1 && n <= 5) {
                return String.valueOf("ABCDE".charAt(n - 1));
            }
        } catch (NumberFormatException ignored) {
            // garder la valeur brute
        }
        return raw;
    }

    /**
     * Construit un message lisible pour une condition Quality Gate en échec.
     */
    private String buildQualityGateConditionErrorDescription(String metricKey, String actualValue, String errorThreshold, String comparator) {
        if (metricKey == null) metricKey = "";
        String metricLabel = frenchQualityGateMetricLabel(metricKey);
        String actual = formatSonarRatingForMessage(metricKey, actualValue != null ? actualValue : "0");
        String required = formatSonarRatingForMessage(metricKey, errorThreshold != null ? errorThreshold : "–");
        // Comparateur: LT = inférieur à, GT = supérieur à, EQ = égal
        String opLabel = "LT".equalsIgnoreCase(comparator) ? "≥"
                : "GT".equalsIgnoreCase(comparator) ? "≤"
                : "≥";
        return String.format("La valeur actuelle (%s) ne respecte pas le seuil requis (%s %s). Améliorez la métrique \"%s\" pour passer le Quality Gate.",
                actual, opLabel, required, metricLabel);
    }

    /** Libellé français pour une métrique Quality Gate Sonar (clé technique → libellé UI). */
    private String frenchQualityGateMetricLabel(String metricKey) {
        if (metricKey == null || metricKey.isBlank()) {
            return "Métrique";
        }
        String k = metricKey.toLowerCase();
        if (k.contains("coverage")) {
            return k.contains("new") ? "Couverture sur le nouveau code" : "Couverture";
        }
        if (k.contains("security_hotspots")) {
            return "Points sensibles revus";
        }
        if (k.contains("duplicated")) {
            return "Duplication";
        }
        if (k.contains("reliability_rating")) {
            return k.contains("new") ? "Note de fiabilité (nouveau code)" : "Note de fiabilité";
        }
        if (k.contains("security_rating")) {
            return k.contains("new") ? "Note de sécurité (nouveau code)" : "Note de sécurité";
        }
        if (k.contains("maintainability_rating") || k.contains("sqale_rating")) {
            return k.contains("new") ? "Note de maintenabilité (nouveau code)" : "Note de maintenabilité";
        }
        if (k.contains("vulnerabilit")) {
            return k.contains("new") ? "Vulnérabilités (nouveau code)" : "Vulnérabilités";
        }
        if (k.contains("bugs") || k.equals("reliability_remediation_effort")) {
            return k.contains("new") ? "Bugs (nouveau code)" : "Bugs";
        }
        if (k.contains("code_smell") || k.contains("sqale_index")) {
            return k.contains("new") ? "Code smells (nouveau code)" : "Code smells";
        }
        if (k.contains("open_issues")) {
            return "Problèmes ouverts";
        }
        if (k.contains("accepted_issues")) {
            return "Problèmes acceptés";
        }
        return metricKey;
    }

    private String sonarUrlEncode(String value) {
        if (value == null) return "";
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /** Base URL Sonar (sans slash final, avec schéma https). */
    private String normalizeSonarHostUrl() {
        if (sonarHostUrl == null || sonarHostUrl.isBlank()) {
            return "https://sonarcloud.io";
        }
        String url = sonarHostUrl.trim();
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "https://" + url;
        }
        return url.replaceAll("/+$", "");
    }

    /** Construit une URI Sonar valide (encode correct des query params, ex. metricKeys avec virgules). */
    private URI buildSonarUri(String apiPath, MultiValueMap<String, String> queryParams) {
        String path = apiPath.startsWith("/") ? apiPath : "/" + apiPath;
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(normalizeSonarHostUrl()).path(path);
        if (queryParams != null) {
            queryParams.forEach((key, values) -> {
                for (String value : values) {
                    if (value != null) {
                        builder.queryParam(key, value);
                    }
                }
            });
        }
        return builder.build().encode().toUri();
    }

    private URI buildSonarUri(String apiPath, String queryKey, String queryValue) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(queryKey, queryValue);
        return buildSonarUri(apiPath, params);
    }

    private static final String SONAR_MEASURE_KEYS =
            "bugs,vulnerabilities,code_smells,coverage,duplicated_lines_density,ncloc,security_hotspots,"
                    + "security_rating,reliability_rating,sqale_rating,"
                    + "blocker_violations,critical_violations,major_violations,minor_violations,info_violations,"
                    + "software_quality_security_issues,software_quality_reliability_issues,software_quality_maintainability_issues,"
                    + "software_quality_security_rating,software_quality_reliability_rating,software_quality_maintainability_rating,"
                    + "software_quality_high_severity_issues,software_quality_medium_severity_issues,software_quality_low_severity_issues,"
                    + "software_quality_security_high_issues,software_quality_security_medium_issues,software_quality_security_low_issues,"
                    + "software_quality_reliability_high_issues,software_quality_reliability_medium_issues,software_quality_reliability_low_issues,"
                    + "software_quality_maintainability_high_issues,software_quality_maintainability_medium_issues,software_quality_maintainability_low_issues";

    private HttpEntity<String> sonarAuthEntity() {
        HttpHeaders headers = sonarAuthHeaders();
        return new HttpEntity<>(headers);
    }

    private HttpHeaders sonarAuthHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", sonarAuthorizationHeader());
        if (sonarAcceptLanguage != null && !sonarAcceptLanguage.isBlank()) {
            headers.add(HttpHeaders.ACCEPT_LANGUAGE, sonarAcceptLanguage.trim());
        }
        return headers;
    }

    /** Paramètres locale/language pour /api/rules/show (descriptions FR si disponibles). */
    private void addSonarRuleLocaleParams(MultiValueMap<String, String> params) {
        String lang = (sonarAcceptLanguage == null || sonarAcceptLanguage.isBlank())
                ? "fr" : sonarAcceptLanguage.trim();
        params.add("locale", lang);
        params.add("language", lang);
    }

    @SuppressWarnings("unchecked")
    private void translateSonarRuleMapToFrench(Map<String, Object> ruleMap, String ruleKeyFallback) {
        if (ruleMap == null) {
            return;
        }
        String ruleKey = ruleMap.get("key") != null
                ? String.valueOf(ruleMap.get("key"))
                : (ruleKeyFallback != null ? ruleKeyFallback : "unknown");

        translateRuleTextField(ruleMap, "htmlDesc", ruleKey + "_htmlDesc");
        translateRuleTextField(ruleMap, "mdDesc", ruleKey + "_mdDesc");
        translateRuleTextField(ruleMap, "riskDescription", ruleKey + "_riskDescription");
        translateRuleTextField(ruleMap, "vulnerabilityDescription", ruleKey + "_vulnerabilityDescription");
        translateRuleTextField(ruleMap, "fixRecommendations", ruleKey + "_fixRecommendations");
        translateRuleTextField(ruleMap, "htmlNote", ruleKey + "_htmlNote");

        Object sections = ruleMap.get("descriptionSections");
        if (sections instanceof java.util.List<?> list) {
            for (Object item : list) {
                if (!(item instanceof Map<?, ?> section)) {
                    continue;
                }
                Map<String, Object> sec = (Map<String, Object>) section;
                String sectionKey = sec.get("key") != null ? String.valueOf(sec.get("key")) : "section";
                String suffix = ruleKey + "_sec_" + sectionKey;
                translateRuleTextField(sec, "htmlContent", suffix + "_htmlContent");
                translateRuleTextField(sec, "content", suffix + "_content");
            }
        }
    }

    private void translateRuleTextField(Map<String, Object> map, String field, String cacheKey) {
        Object value = map.get(field);
        if (value instanceof String text && !text.isBlank()) {
            map.put(field, translationService.translateToFrench(text, cacheKey));
        }
    }

    @SuppressWarnings("unchecked")
    private void translateSonarIssueMessage(Map<String, Object> result, String ruleKey) {
        Object issueObj = result.get("issue");
        if (!(issueObj instanceof Map<?, ?> issueMap)) {
            return;
        }
        translateIssueMessageMap((Map<String, Object>) issueMap);
    }

    @SuppressWarnings("unchecked")
    private void translateSonarHotspotMessage(Map<String, Object> result, String ruleKey) {
        Object hotspotObj = result.get("hotspot");
        if (!(hotspotObj instanceof Map<?, ?> hotspotMap)) {
            return;
        }
        translateHotspotMessageMap((Map<String, Object>) hotspotMap, ruleKey);
    }

    private void translateIssueMessageMap(Map<String, Object> issue) {
        if (issue == null) {
            return;
        }
        Object message = issue.get("message");
        if (message instanceof String text && !text.isBlank()) {
            String ruleKey = issue.get("rule") != null
                    ? String.valueOf(issue.get("rule"))
                    : String.valueOf(issue.getOrDefault("key", "issue"));
            issue.put("message", translationService.translateToFrench(text, ruleKey + "_message"));
        }
    }

    private void translateHotspotMessageMap(Map<String, Object> hotspot, String ruleKeyFallback) {
        if (hotspot == null) {
            return;
        }
        Object message = hotspot.get("message");
        if (message instanceof String text && !text.isBlank()) {
            String ruleKey = ruleKeyFallback != null ? ruleKeyFallback
                    : (hotspot.get("ruleKey") != null
                    ? String.valueOf(hotspot.get("ruleKey"))
                    : String.valueOf(hotspot.getOrDefault("key", "hotspot")));
            hotspot.put("message", translationService.translateToFrench(text, ruleKey + "_hotspot_message"));
        }
    }

    @SuppressWarnings("unchecked")
    private void syncTranslatedHotspotRule(Map<String, Object> result) {
        Object rule = result.get("rule");
        if (!(rule instanceof Map<?, ?>)) {
            return;
        }
        Object hotspotObj = result.get("hotspot");
        if (hotspotObj instanceof Map<?, ?> hotspotMap) {
            ((Map<String, Object>) hotspotMap).put("rule", rule);
        }
    }

    @SuppressWarnings("unchecked")
    private void translateSonarListsInResult(Map<String, Object> result) {
        Object issuesObj = result.get("issues");
        if (issuesObj instanceof com.fasterxml.jackson.databind.node.ArrayNode arr) {
            result.put("issues", translateSonarIssuesNode(arr));
        } else if (issuesObj instanceof List<?> list && !list.isEmpty()) {
            List<Map<String, Object>> translated = new ArrayList<>();
            for (Object item : list) {
                if (item instanceof JsonNode node) {
                    Map<String, Object> issue = objectMapper.convertValue(node, Map.class);
                    translateIssueMessageMap(issue);
                    translated.add(issue);
                } else if (item instanceof Map<?, ?> issue) {
                    Map<String, Object> issueMap = (Map<String, Object>) issue;
                    translateIssueMessageMap(issueMap);
                    translated.add(issueMap);
                }
            }
            if (!translated.isEmpty()) {
                result.put("issues", translated);
            }
        }

        Object hotspotsObj = result.get("hotspots");
        if (hotspotsObj instanceof JsonNode arr && arr.isArray()) {
            result.put("hotspots", translateSonarHotspotsNode(arr));
        } else if (hotspotsObj instanceof List<?> list && !list.isEmpty()) {
            List<Map<String, Object>> translated = new ArrayList<>();
            for (Object item : list) {
                if (item instanceof JsonNode node) {
                    Map<String, Object> hotspot = objectMapper.convertValue(node, Map.class);
                    translateHotspotMessageMap(hotspot, node.path("ruleKey").asText(null));
                    translated.add(hotspot);
                } else if (item instanceof Map<?, ?> hotspot) {
                    Map<String, Object> hotspotMap = (Map<String, Object>) hotspot;
                    String ruleKey = hotspot.get("ruleKey") != null
                            ? String.valueOf(hotspot.get("ruleKey")) : null;
                    translateHotspotMessageMap(hotspotMap, ruleKey);
                    translated.add(hotspotMap);
                }
            }
            if (!translated.isEmpty()) {
                result.put("hotspots", translated);
            }
        }
    }

    private List<Map<String, Object>> translateSonarIssuesNode(com.fasterxml.jackson.databind.node.ArrayNode allIssues) {
        List<Map<String, Object>> translated = new ArrayList<>();
        for (JsonNode item : allIssues) {
            Map<String, Object> issue = objectMapper.convertValue(item, Map.class);
            translateIssueMessageMap(issue);
            translated.add(issue);
        }
        return translated;
    }

    private List<Map<String, Object>> translateSonarHotspotsNode(JsonNode hotspotsArray) {
        List<Map<String, Object>> translated = new ArrayList<>();
        if (!hotspotsArray.isArray()) {
            return translated;
        }
        for (JsonNode item : hotspotsArray) {
            Map<String, Object> hotspot = objectMapper.convertValue(item, Map.class);
            String ruleKey = item.path("ruleKey").asText(null);
            translateHotspotMessageMap(hotspot, ruleKey);
            translated.add(hotspot);
        }
        return translated;
    }

    /** SonarCloud : Bearer ; SonarQube self-hosted : Basic token: (aligné pipeline curl -u). */
    private String sonarAuthorizationHeader() {
        if (sonarToken == null || sonarToken.isBlank()) {
            return "Bearer ";
        }
        boolean sonarCloud = sonarHostUrl != null && sonarHostUrl.contains("sonarcloud");
        if (sonarCloud) {
            return "Bearer " + sonarToken;
        }
        String raw = sonarToken + ":";
        return "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> getOrCreateSonarMetrics(Map<String, Object> result) {
        Object m = result.get("metrics");
        if (m instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }
        Map<String, Object> metrics = new LinkedHashMap<>();
        result.put("metrics", metrics);
        return metrics;
    }

    private void putSonarMetricIfAbsent(Map<String, Object> metrics, String key, Object value) {
        if (value == null) return;
        Object existing = metrics.get(key);
        if (existing == null || "0".equals(String.valueOf(existing)) || "".equals(String.valueOf(existing))) {
            metrics.put(key, value);
        }
    }

    /**
     * Récupère le statut Quality Gate SonarQube/SonarCloud (API project_status), optionnellement par branche.
     */
    public Map<String, Object> fetchSonarQualityGateStatus(String projectKey, String branch) {
        String pk = (projectKey != null && !projectKey.isBlank()) ? projectKey.trim() : sonarProjectKey;
        try {
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("projectKey", pk);
            if (branch != null && !branch.isBlank()) {
                params.add("branch", branch.trim());
            }
            RestTemplate restTemplate = sonarRestTemplate;
            ResponseEntity<JsonNode> response = restTemplate.exchange(
                    buildSonarUri("/api/qualitygates/project_status", params),
                    HttpMethod.GET, sonarAuthEntity(), JsonNode.class);
            if (response.getBody() != null && response.getBody().has("projectStatus")) {
                return normalizeQualityGateStatus(response.getBody().get("projectStatus"));
            }
        } catch (Exception e) {
            log.warn("⚠️ Quality Gate Sonar (projectKey={}, branch={}): {}", pk, branch, e.getMessage());
        }
        return Map.of();
    }

    /**
     * Complète metrics à partir des conditions du Quality Gate (actualValue).
     */
    @SuppressWarnings("unchecked")
    public void mergeSonarMetricsFromQualityGate(Map<String, Object> result) {
        if (result == null) return;
        Object qgObj = result.get("quality_gate");
        if (!(qgObj instanceof Map<?, ?> qg)) return;
        Object condObj = qg.get("conditions");
        if (!(condObj instanceof List<?> conditions)) return;

        Map<String, String> aliases = Map.ofEntries(
                Map.entry("bugs", "bugs"),
                Map.entry("new_bugs", "bugs"),
                Map.entry("vulnerabilities", "vulnerabilities"),
                Map.entry("new_vulnerabilities", "vulnerabilities"),
                Map.entry("code_smells", "code_smells"),
                Map.entry("new_code_smells", "code_smells"),
                Map.entry("coverage", "coverage"),
                Map.entry("new_coverage", "coverage"),
                Map.entry("duplicated_lines_density", "duplicated_lines_density"),
                Map.entry("new_duplicated_lines_density", "duplicated_lines_density"),
                Map.entry("security_hotspots", "security_hotspots"),
                Map.entry("new_security_hotspots", "security_hotspots"),
                Map.entry("security_rating", "security_rating"),
                Map.entry("new_security_rating", "security_rating"),
                Map.entry("reliability_rating", "reliability_rating"),
                Map.entry("new_reliability_rating", "reliability_rating"),
                Map.entry("sqale_rating", "sqale_rating"),
                Map.entry("new_maintainability_rating", "sqale_rating"),
                Map.entry("maintainability_rating", "maintainability_rating"),
                Map.entry("software_quality_security_rating", "software_quality_security_rating"),
                Map.entry("software_quality_reliability_rating", "software_quality_reliability_rating"),
                Map.entry("software_quality_maintainability_rating", "software_quality_maintainability_rating")
        );

        Map<String, Object> metrics = getOrCreateSonarMetrics(result);
        for (Object item : conditions) {
            if (!(item instanceof Map<?, ?> cond)) continue;
            String metricKey = String.valueOf(cond.get("metricKey"));
            if ("null".equals(metricKey) || metricKey.isBlank()) {
                metricKey = String.valueOf(cond.get("metric"));
            }
            Object actual = cond.get("actualValue");
            if (actual == null) actual = cond.get("actual");
            String target = aliases.get(metricKey);
            if (target == null && aliases.containsKey(metricKey.toLowerCase(Locale.ROOT))) {
                target = aliases.get(metricKey.toLowerCase(Locale.ROOT));
            }
            if (target == null && (metricKey.contains("bug") || metricKey.contains("vulnerabilit")
                    || metricKey.contains("smell") || metricKey.contains("coverage")
                    || metricKey.contains("duplic") || metricKey.contains("hotspot"))) {
                target = metricKey;
            }
            if (target == null && metricKey.toLowerCase(Locale.ROOT).contains("rating")) {
                target = metricKey;
            }
            if (target != null) {
                putSonarMetricIfAbsent(metrics, target, actual);
            }
        }
        enrichSonarDerivedFromMeasures(result);
    }

    /**
     * Complète bugs/vulnérabilités/code smells depuis les facettes issues/search.
     */
    public void enrichSonarMetricsFromIssueFacets(Map<String, Object> result) {
        if (result == null) return;
        Object facetsObj = result.get("issue_facets");
        if (facetsObj == null) return;
        JsonNode facets = facetsObj instanceof JsonNode ? (JsonNode) facetsObj : objectMapper.valueToTree(facetsObj);
        if (!facets.isArray()) return;

        Map<String, Object> metrics = getOrCreateSonarMetrics(result);
        for (JsonNode facet : facets) {
            if (!"types".equals(facet.path("property").asText())) continue;
            for (JsonNode val : facet.path("values")) {
                String type = val.path("val").asText("");
                int count = val.path("count").asInt(0);
                switch (type) {
                    case "BUG" -> putSonarMetricIfAbsent(metrics, "bugs", count);
                    case "VULNERABILITY" -> putSonarMetricIfAbsent(metrics, "vulnerabilities", count);
                    case "CODE_SMELL" -> putSonarMetricIfAbsent(metrics, "code_smells", count);
                    default -> { }
                }
            }
        }
    }

    /**
     * Fusionne les métriques Sonar (branche + global).
     */
    @SuppressWarnings("unchecked")
    public void mergeSonarResults(Map<String, Object> target, Map<String, Object> fallback) {
        if (target == null || fallback == null || fallback.isEmpty()) return;
        Map<String, Object> tMetrics = getOrCreateSonarMetrics(target);
        Object fMetrics = fallback.get("metrics");
        if (fMetrics instanceof Map<?, ?> fm) {
            fm.forEach((k, v) -> putSonarMetricIfAbsent(tMetrics, String.valueOf(k), v));
        }
        if (!target.containsKey("quality_gate") && fallback.containsKey("quality_gate")) {
            target.put("quality_gate", fallback.get("quality_gate"));
        }
        if (target.get("total_issues") == null && fallback.get("total_issues") != null) {
            target.put("total_issues", fallback.get("total_issues"));
        }
        if (target.get("issue_facets") == null && fallback.get("issue_facets") != null) {
            target.put("issue_facets", fallback.get("issue_facets"));
        }
    }

    public boolean isSonarMetricsEmpty(Map<String, Object> sonar) {
        if (sonar == null || sonar.isEmpty()) return true;
        Object m = sonar.get("metrics");
        if (!(m instanceof Map<?, ?> metrics) || metrics.isEmpty()) {
            return sonar.get("quality_gate") == null;
        }
        int bugs = parseIntSafe(metrics.get("bugs"));
        int vulns = parseIntSafe(metrics.get("vulnerabilities"));
        int smells = parseIntSafe(metrics.get("code_smells"));
        boolean hasSq = parseIntSafe(metrics.get("software_quality_security_issues")) > 0
                || metrics.containsKey("software_quality_security_rating");
        boolean hasViolations = parseIntSafe(metrics.get("blocker_violations")) > 0
                || parseIntSafe(metrics.get("critical_violations")) > 0;
        return bugs == 0 && vulns == 0 && smells == 0 && !hasSq && !hasViolations
                && sonar.get("quality_gate") == null;
    }

    private int parseIntSafe(Object o) {
        if (o == null) return 0;
        try {
            return (int) Math.round(Double.parseDouble(String.valueOf(o)));
        } catch (Exception e) {
            return 0;
        }
    }

    /** Lit la valeur d'une mesure Sonar (value ou periods[0].value). */
    private String extractSonarMeasureValue(JsonNode measure) {
        if (measure == null || measure.isMissingNode()) return "";
        String direct = measure.path("value").asText("");
        if (direct != null && !direct.isBlank()) return direct.trim();
        JsonNode periods = measure.path("periods");
        if (periods.isArray() && !periods.isEmpty()) {
            String periodVal = periods.get(0).path("value").asText("");
            if (periodVal != null && !periodVal.isBlank()) return periodVal.trim();
        }
        return "";
    }

    private void putSonarMetricsFromMeasuresArray(Map<String, Object> metrics, JsonNode measures) {
        if (measures == null || !measures.isArray()) return;
        for (JsonNode measure : measures) {
            String metric = measure.path("metric").asText("");
            if (metric.isBlank()) continue;
            String value = extractSonarMeasureValue(measure);
            if (!value.isBlank()) {
                metrics.put(metric, value);
            }
        }
    }

    private boolean hasSonarRatingMetric(Map<String, Object> metrics, String ratingKey) {
        if (metrics == null) return false;
        Object raw = metrics.get(ratingKey);
        if (raw == null || String.valueOf(raw).isBlank()) return false;
        return sonarRatingToLetter(raw) != null;
    }

    /**
     * Dérive security/reliability/sqale ratings depuis les issues ouvertes si l'API measures ne les fournit pas.
     */
    @SuppressWarnings("unchecked")
    private void deriveRatingsFromOpenIssues(Map<String, Object> result) {
        if (result == null) return;
        Object issuesObj = result.get("issues");
        if (!(issuesObj instanceof List<?> issues) || issues.isEmpty()) return;

        Map<String, Object> metrics = getOrCreateSonarMetrics(result);
        if (!hasSonarRatingMetric(metrics, "security_rating")) {
            int rating = worstOpenIssueSeverityRating(issues, "VULNERABILITY", 1);
            putSonarNumericRating(metrics, "security_rating", rating);
        }
        if (!hasSonarRatingMetric(metrics, "reliability_rating")) {
            int rating = worstOpenIssueSeverityRating(issues, "BUG", 1);
            putSonarNumericRating(metrics, "reliability_rating", rating);
        }
        if (!hasSonarRatingMetric(metrics, "sqale_rating") && !hasSonarRatingMetric(metrics, "maintainability_rating")) {
            int rating = worstOpenIssueSeverityRating(issues, "CODE_SMELL", 1);
            if (rating <= 1 && parseIntSafe(metrics.get("code_smells")) > 0) {
                int smells = parseIntSafe(metrics.get("code_smells"));
                rating = smells >= 50 ? 3 : 2;
            }
            putSonarNumericRating(metrics, "sqale_rating", rating);
            putSonarNumericRating(metrics, "maintainability_rating", rating);
        }
    }

    private int worstOpenIssueSeverityRating(List<?> issues, String type, int whenNone) {
        int worst = whenNone;
        boolean found = false;
        for (Object item : issues) {
            Map<String, Object> issue = asIssueMap(item);
            if (issue.isEmpty()) continue;
            if (!type.equalsIgnoreCase(String.valueOf(issue.get("type")))) continue;
            String status = String.valueOf(issue.get("status")).toUpperCase(Locale.ROOT);
            if (!Set.of("OPEN", "CONFIRMED", "REOPENED").contains(status)) continue;
            found = true;
            int sev = severityToSonarRating(String.valueOf(issue.get("severity")));
            worst = Math.max(worst, sev);
        }
        return found ? worst : whenNone;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> asIssueMap(Object item) {
        if (item instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            map.forEach((k, v) -> out.put(String.valueOf(k), v));
            return out;
        }
        if (item instanceof JsonNode node && node.isObject()) {
            return objectMapper.convertValue(node, Map.class);
        }
        return Map.of();
    }

    private int severityToSonarRating(String severity) {
        return switch (String.valueOf(severity).toUpperCase(Locale.ROOT)) {
            case "BLOCKER" -> 5;
            case "CRITICAL" -> 4;
            case "MAJOR" -> 3;
            case "MINOR", "INFO" -> 2;
            default -> 2;
        };
    }

    private void putSonarNumericRating(Map<String, Object> metrics, String key, int rating) {
        if (rating < 1 || rating > 5) return;
        metrics.put(key, String.valueOf(rating));
        String letter = sonarRatingToLetter(rating);
        if (letter != null) {
            metrics.put(key + "_letter", letter);
        }
    }

    /**
     * Récupère les résultats SonarQube pour un projet (métriques globales, issues, hotspots, quality gate).
     */
    public Map<String, Object> getSonarQubeResults() {
        try {
            log.info("🔍 Récupération des résultats SonarQube pour le projet: {}", sonarProjectKey);

            RestTemplate restTemplate = sonarRestTemplate;
            HttpEntity<String> entity = sonarAuthEntity();

            // 1. Métriques principales
            MultiValueMap<String, String> measureParams = new LinkedMultiValueMap<>();
            measureParams.add("component", sonarProjectKey);
            measureParams.add("metricKeys",
                    "bugs,vulnerabilities,code_smells,coverage,duplicated_lines_density,ncloc,security_hotspots,security_rating,reliability_rating,sqale_rating");
            ResponseEntity<JsonNode> measuresResponse = restTemplate.exchange(
                    buildSonarUri("/api/measures/component", measureParams),
                    HttpMethod.GET,
                    entity,
                    JsonNode.class
            );

            // 2. Issues (avec facettes principales pour les filtres frontend)
            MultiValueMap<String, String> issueParams = new LinkedMultiValueMap<>();
            issueParams.add("componentKeys", sonarProjectKey);
            issueParams.add("ps", "500");
            issueParams.add("additionalFields", "_all");
            issueParams.add("statuses", "OPEN,CONFIRMED,REOPENED,RESOLVED,CLOSED");
            issueParams.add("facets", "severities,types,statuses,languages,tags,assignees,resolutions");

            // SonarCloud: le max renvoyé par requête est 500. On pagine donc pour avoir le bon total.
            int pageIndex = 1;
            int totalIssues = 0;
            com.fasterxml.jackson.databind.node.ArrayNode allIssues = objectMapper.createArrayNode();
            JsonNode firstIssuesBody = null;
            while (true) {
                MultiValueMap<String, String> pageParams = new LinkedMultiValueMap<>(issueParams);
                pageParams.add("p", String.valueOf(pageIndex));
                ResponseEntity<JsonNode> issuesResponsePage = restTemplate.exchange(
                        buildSonarUri("/api/issues/search", pageParams),
                        HttpMethod.GET,
                        entity,
                        JsonNode.class
                );
                JsonNode issuesBodyPage = issuesResponsePage.getBody();
                if (issuesBodyPage == null) break;
                if (firstIssuesBody == null) firstIssuesBody = issuesBodyPage;
                if (totalIssues == 0) totalIssues = issuesBodyPage.path("total").asInt(0);

                JsonNode issuesPageArr = issuesBodyPage.path("issues");
                if (!issuesPageArr.isArray() || issuesPageArr.size() == 0) break;
                for (JsonNode item : issuesPageArr) {
                    allIssues.add(item);
                }

                if (allIssues.size() >= totalIssues) break;
                pageIndex++;
                // Sécurité: le endpoint a une limite totale pratique (souvent 10000). On évite une boucle infinie.
                if (pageIndex > 50) break;
            }

            // 3. Hotspots de sécurité
            MultiValueMap<String, String> hotspotParams = new LinkedMultiValueMap<>();
            hotspotParams.add("projectKey", sonarProjectKey);
            hotspotParams.add("ps", "100");
            ResponseEntity<JsonNode> hotspotsResponse = restTemplate.exchange(
                    buildSonarUri("/api/hotspots/search", hotspotParams),
                    HttpMethod.GET,
                    entity,
                    JsonNode.class
            );

            Map<String, Object> result = new HashMap<>();

            // Métriques
            if (measuresResponse.getBody() != null && measuresResponse.getBody().has("component")) {
                JsonNode component = measuresResponse.getBody().get("component");
                JsonNode measures = component.get("measures");

                Map<String, Object> metrics = new HashMap<>();
                putSonarMetricsFromMeasuresArray(metrics, measures);
                result.put("metrics", metrics);
            }
            // Exposer host & project pour permettre des liens directs dans le front
            result.put("sonar_host_url", sonarHostUrl);
            result.put("sonar_project_key", sonarProjectKey);

            // Issues (+ facettes pour les filtres frontend)
            if (firstIssuesBody != null) {
                result.put("total_issues", totalIssues);
                result.put("issues", allIssues);
                result.put("issue_facets", firstIssuesBody.path("facets"));
            }

            // Hotspots (total peut être absent ou 0 : utiliser la taille de la liste)
            if (hotspotsResponse.getBody() != null) {
                JsonNode hotspotsBody = hotspotsResponse.getBody();
                JsonNode hotspotsArray = hotspotsBody.path("hotspots");
                int totalFromApi = hotspotsBody.path("total").asInt(0);
                int count = hotspotsArray.isArray() ? hotspotsArray.size() : 0;
                result.put("total_hotspots", Math.max(totalFromApi, count));
                result.put("hotspots", hotspotsArray);
            }

            // Duplication par fichier (component tree, fichiers uniquement)
            try {
                MultiValueMap<String, String> dupParams = new LinkedMultiValueMap<>();
                dupParams.add("component", sonarProjectKey);
                dupParams.add("metricKeys", "duplicated_lines_density");
                dupParams.add("qualifiers", "FIL");
                dupParams.add("ps", "100");
                ResponseEntity<JsonNode> dupResponse = restTemplate.exchange(
                        buildSonarUri("/api/measures/component_tree", dupParams),
                        HttpMethod.GET,
                        entity,
                        JsonNode.class
                );

                if (dupResponse.getBody() != null) {
                    result.put("duplication_components", dupResponse.getBody().path("components"));
                }
            } catch (Exception e) {
                log.warn("⚠️ Impossible de récupérer le détail de duplication par fichier: {}", e.getMessage());
            }

            // Couverture par fichier (pour Quality Gate Coverage)
            try {
                MultiValueMap<String, String> covParams = new LinkedMultiValueMap<>();
                covParams.add("component", sonarProjectKey);
                covParams.add("metricKeys", "coverage,uncovered_lines,uncovered_conditions");
                covParams.add("qualifiers", "FIL");
                covParams.add("ps", "100");
                ResponseEntity<JsonNode> covResponse = restTemplate.exchange(
                        buildSonarUri("/api/measures/component_tree", covParams),
                        HttpMethod.GET,
                        entity,
                        JsonNode.class
                );

                if (covResponse.getBody() != null) {
                    result.put("coverage_components", covResponse.getBody().path("components"));
                }
            } catch (Exception e) {
                log.warn("⚠️ Impossible de récupérer le détail de couverture par fichier: {}", e.getMessage());
            }

            // Quality Gate
            MultiValueMap<String, String> qgParams = new LinkedMultiValueMap<>();
            qgParams.add("projectKey", sonarProjectKey);
            ResponseEntity<JsonNode> qualityGateResponse = restTemplate.exchange(
                    buildSonarUri("/api/qualitygates/project_status", qgParams),
                    HttpMethod.GET,
                    entity,
                    JsonNode.class
            );

            if (qualityGateResponse.getBody() != null && qualityGateResponse.getBody().has("projectStatus")) {
                JsonNode projectStatus = qualityGateResponse.getBody().get("projectStatus");
                result.put("quality_gate", normalizeQualityGateStatus(projectStatus));
            }

            mergeSonarMetricsFromQualityGate(result);
            enrichSonarMetricsFromIssueFacets(result);
            deriveRatingsFromOpenIssues(result);
            enrichSonarDerivedFromMeasures(result);

            translateSonarListsInResult(result);
            log.info("✅ Résultats SonarQube récupérés avec succès");
            return result;

        } catch (Exception e) {
            log.error("❌ Erreur récupération résultats SonarQube: {}", e.getMessage());
            throw new RuntimeException("Impossible de récupérer les résultats SonarQube", e);
        }
    }

    /**
     * Change le statut d'une issue SonarQube/SonarCloud (persisté côté SonarCloud).
     * Transitions possibles: confirm, unconfirm, resolve, reopen, falsepositive, wontfix, accept.
     */
    public void sonarIssueDoTransition(String issueKey, String transition) {
        if (issueKey == null || issueKey.isBlank() || transition == null || transition.isBlank()) {
            throw new IllegalArgumentException("issueKey et transition sont requis");
        }
        String url = normalizeSonarHostUrl() + "/api/issues/do_transition";
        RestTemplate restTemplate = sonarRestTemplate;
        HttpHeaders headers = sonarAuthHeaders();
        headers.setContentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("issue", issueKey);
        body.add("transition", transition);
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);
        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Transition échouée: " + response.getStatusCode());
        }
        log.info("✅ Issue {} transition vers {}", issueKey, transition);
    }

    /**
     * Assigne ou désassigne une issue SonarQube/SonarCloud (persisté côté SonarCloud).
     * @param issueKey clé de l'issue
     * @param assignee login utilisateur SonarCloud, ou null/empty pour désassigner
     */
    public void sonarIssueAssign(String issueKey, String assignee) {
        if (issueKey == null || issueKey.isBlank()) {
            throw new IllegalArgumentException("issueKey est requis");
        }
        String url = normalizeSonarHostUrl() + "/api/issues/assign";
        RestTemplate restTemplate = sonarRestTemplate;
        HttpHeaders headers = sonarAuthHeaders();
        headers.setContentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("issue", issueKey);
        if (assignee != null && !assignee.isBlank()) {
            body.add("assignee", assignee);
        }
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);
        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Assignation échouée: " + response.getStatusCode());
        }
        log.info("✅ Issue {} assignée à {}", issueKey, assignee != null ? assignee : "(désassignée)");
    }

    /**
     * Assigne l'issue au compte SonarCloud par défaut (utilisé pour \"Assign to me\" côté plateforme).
     */
    public void sonarIssueAssignToDefault(String issueKey) {
        if (sonarDefaultAssignee == null || sonarDefaultAssignee.isBlank()) {
            throw new IllegalStateException("sonarqube.default-assignee n'est pas configuré côté backend");
        }
        sonarIssueAssign(issueKey, sonarDefaultAssignee);
    }

    /**
     * Désassigne complètement l'issue (équivalent Not assigned).
     */
    public void sonarIssueUnassign(String issueKey) {
        sonarIssueAssign(issueKey, null);
    }

    /**
     * Récupère les résultats SonarQube pour une branche spécifique.
     * Résilient : échec d'une sous-API n'annule pas les autres ; Quality Gate via project_status + branche.
     */
    public Map<String, Object> getSonarQubeResultsForBranch(String branch) {
        return getSonarQubeResultsForBranch(branch, null);
    }

    public Map<String, Object> getSonarQubeResultsForBranch(String branch, String overrideProjectKey) {
        String effectiveProjectKey = (overrideProjectKey != null && !overrideProjectKey.isBlank())
                ? overrideProjectKey : sonarProjectKey;

        Map<String, Object> result = loadSonarDataForProjectBranch(effectiveProjectKey, branch);

        boolean hasOverrideKey = overrideProjectKey != null && !overrideProjectKey.isBlank();
        if (isSonarMetricsEmpty(result) && !hasOverrideKey) {
            try {
                Map<String, Object> global = getSonarQubeResults();
                mergeSonarResults(result, global);
                mergeSonarMetricsFromQualityGate(result);
                enrichSonarMetricsFromIssueFacets(result);
                deriveRatingsFromOpenIssues(result);
                enrichSonarDerivedFromMeasures(result);
            } catch (Exception e) {
                log.warn("⚠️ Fallback Sonar global échoué: {}", e.getMessage());
            }
        } else if (isSonarMetricsEmpty(result) && hasOverrideKey) {
            log.warn("⚠️ Sonar vide pour projectKey={} branch={} — pas de fallback sur le projet template",
                    effectiveProjectKey, branch);
        }

        result.put("branch", branch);
        result.put("sonar_host_url", normalizeSonarHostUrl());
        result.put("sonar_project_key", effectiveProjectKey);

        log.info("✅ SonarQube branch={} metrics={} qg={}",
                branch, result.get("metrics"), result.containsKey("quality_gate"));
        translateSonarListsInResult(result);
        return result;
    }

    /**
     * Liste les branches analysées d'un projet SonarQube (community branch plugin).
     */
    public List<String> listSonarProjectBranches(String projectKey) {
        return fetchSonarBranchEntries(projectKey).stream()
                .map(e -> String.valueOf(e.get("name")))
                .filter(n -> !n.isBlank())
                .toList();
    }

    /**
     * Résout la branche Sonar à interroger : si la branche demandée n'existe pas,
     * retombe sur la branche principale (isMain=true).
     */
    public SonarBranchResolution resolveSonarBranch(String projectKey, String requestedBranch) {
        if (projectKey == null || projectKey.isBlank()) {
            return SonarBranchResolution.builder()
                    .requestedBranch(requestedBranch)
                    .sonarReachable(false)
                    .availableBranches(List.of())
                    .build();
        }
        List<Map<String, Object>> entries = fetchSonarBranchEntries(projectKey);
        List<String> names = entries.stream()
                .map(e -> String.valueOf(e.get("name")))
                .filter(n -> !n.isBlank())
                .toList();
        if (names.isEmpty()) {
            return SonarBranchResolution.builder()
                    .requestedBranch(requestedBranch)
                    .sonarReachable(false)
                    .availableBranches(List.of())
                    .build();
        }
        String mainBranch = entries.stream()
                .filter(e -> Boolean.TRUE.equals(e.get("isMain")))
                .map(e -> String.valueOf(e.get("name")))
                .findFirst()
                .orElse(names.get(0));

        String req = requestedBranch != null && !requestedBranch.isBlank() ? requestedBranch.trim() : null;
        if (req != null && names.contains(req)) {
            return SonarBranchResolution.builder()
                    .requestedBranch(req)
                    .resolvedBranch(req)
                    .branchFallback(false)
                    .availableBranches(names)
                    .sonarReachable(true)
                    .build();
        }

        String message = req != null
                ? String.format(
                "Branche « %s » non analysée dans SonarQube — affichage de la branche principale « %s ».",
                req, mainBranch)
                : null;
        return SonarBranchResolution.builder()
                .requestedBranch(req)
                .resolvedBranch(mainBranch)
                .branchFallback(req != null)
                .fallbackMessage(message)
                .availableBranches(names)
                .sonarReachable(true)
                .build();
    }

    /**
     * Point d'entrée Quality Gate : résolution branche + métriques par projectKey dérivé du repo.
     */
    public Map<String, Object> fetchSonarForQualityGate(String projectKey, String requestedBranch) {
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("sonar_host_url", sonarHostUrl);
        envelope.put("sonar_project_key", projectKey);

        SonarBranchResolution resolution = resolveSonarBranch(projectKey, requestedBranch);
        envelope.put("branch_resolution", resolution);
        envelope.put("requested_branch", resolution.getRequestedBranch());

        if (!resolution.isSonarReachable() || resolution.getResolvedBranch() == null) {
            String fallbackBranch = requestedBranch != null && !requestedBranch.isBlank()
                    ? requestedBranch.trim() : "main";
            Map<String, Object> direct = loadSonarDataForProjectBranch(projectKey, fallbackBranch);
            if (isSonarMetricsEmpty(direct) && !fallbackBranch.equals("main")) {
                direct = loadSonarDataForProjectBranch(projectKey, "main");
                fallbackBranch = "main";
            }
            if (!isSonarMetricsEmpty(direct) || direct.containsKey("quality_gate")) {
                envelope.putAll(direct);
                envelope.put("branch", fallbackBranch);
                envelope.put("sonar_available", true);
                envelope.put("branch_resolution", SonarBranchResolution.builder()
                        .requestedBranch(requestedBranch)
                        .resolvedBranch(fallbackBranch)
                        .branchFallback(!fallbackBranch.equals(requestedBranch))
                        .sonarReachable(true)
                        .availableBranches(List.of(fallbackBranch))
                        .build());
                return envelope;
            }
            envelope.put("sonar_available", false);
            envelope.put("branch", resolution.getResolvedBranch());
            return envelope;
        }

        Map<String, Object> data = loadSonarDataForProjectBranch(projectKey, resolution.getResolvedBranch());
        envelope.putAll(data);
        envelope.put("branch", resolution.getResolvedBranch());
        if (resolution.getFallbackMessage() != null) {
            envelope.put("branch_fallback_message", resolution.getFallbackMessage());
        }
        boolean available = !isSonarMetricsEmpty(envelope) || envelope.containsKey("quality_gate");
        envelope.put("sonar_available", available);
        return envelope;
    }

    /**
     * Récupère les résultats SonarQube pour un projectKey et une branche déjà résolue.
     */
    public Map<String, Object> getSonarQubeResultsForProjectKey(String projectKey, String branch) {
        if (projectKey == null || projectKey.isBlank()) {
            return Collections.emptyMap();
        }
        Map<String, Object> result = loadSonarDataForProjectBranch(projectKey.trim(), branch);
        result.put("sonar_host_url", sonarHostUrl);
        result.put("sonar_project_key", projectKey.trim());
        if (branch != null && !branch.isBlank()) {
            result.put("branch", branch.trim());
        }
        result.put("sonar_available", !isSonarMetricsEmpty(result) || result.containsKey("quality_gate"));
        return result;
    }

    private List<Map<String, Object>> fetchSonarBranchEntries(String projectKey) {
        try {
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("project", projectKey.trim());
            RestTemplate restTemplate = sonarRestTemplate;
            ResponseEntity<JsonNode> response = restTemplate.exchange(
                    buildSonarUri("/api/project_branches/list", params),
                    HttpMethod.GET, sonarAuthEntity(), JsonNode.class);
            JsonNode body = response.getBody();
            if (body == null || !body.path("branches").isArray()) {
                return List.of();
            }
            List<Map<String, Object>> out = new ArrayList<>();
            for (JsonNode b : body.path("branches")) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("name", b.path("name").asText(""));
                entry.put("isMain", b.path("isMain").asBoolean(false));
                out.add(entry);
            }
            return out;
        } catch (Exception e) {
            log.warn("⚠️ project_branches/list (projectKey={}): {}", projectKey, e.getMessage());
            return List.of();
        }
    }

    private Map<String, Object> loadSonarDataForProjectBranch(String projectKey, String branch) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (projectKey == null || projectKey.isBlank() || branch == null || branch.isBlank()) {
            return result;
        }
        String pk = projectKey.trim();
        String b = branch.trim();
        log.info("🔍 SonarQube load (projectKey={}, branch={})", pk, b);

        RestTemplate restTemplate = sonarRestTemplate;
        HttpEntity<String> entity = sonarAuthEntity();

        // 1) Measures (classiques + Software Quality Sonar 10+)
        try {
            MultiValueMap<String, String> measureParams = new LinkedMultiValueMap<>();
            measureParams.add("component", pk);
            measureParams.add("branch", b);
            measureParams.add("metricKeys", SONAR_MEASURE_KEYS);
            ResponseEntity<JsonNode> measuresResponse = restTemplate.exchange(
                    buildSonarUri("/api/measures/component", measureParams),
                    HttpMethod.GET, entity, JsonNode.class);
            if (measuresResponse.getBody() != null && measuresResponse.getBody().has("component")) {
                JsonNode measures = measuresResponse.getBody().get("component").get("measures");
                Map<String, Object> metrics = new LinkedHashMap<>();
                if (measures != null && measures.isArray()) {
                    putSonarMetricsFromMeasuresArray(metrics, measures);
                }
                result.put("metrics", metrics);
            }
        } catch (Exception e) {
            log.warn("⚠️ Métriques Sonar indisponibles (projectKey={}, branch={}): {}", pk, b, e.getMessage());
        }

        // 2) Issues (facettes types/severities — pas pour Software Quality bySeverity)
        try {
            MultiValueMap<String, String> issueParams = new LinkedMultiValueMap<>();
            issueParams.add("componentKeys", pk);
            issueParams.add("branch", b);
            issueParams.add("ps", "500");
            issueParams.add("additionalFields", "_all");
            issueParams.add("statuses", "OPEN,CONFIRMED,REOPENED,RESOLVED,CLOSED");
            issueParams.add("facets", "severities,types,statuses,languages,tags,assignees,resolutions");
            int pageIndex = 1;
            int totalIssues = 0;
            com.fasterxml.jackson.databind.node.ArrayNode allIssues = objectMapper.createArrayNode();
            JsonNode firstIssuesBody = null;
            while (true) {
                MultiValueMap<String, String> pageParams = new LinkedMultiValueMap<>(issueParams);
                pageParams.add("p", String.valueOf(pageIndex));
                ResponseEntity<JsonNode> issuesResponsePage = restTemplate.exchange(
                        buildSonarUri("/api/issues/search", pageParams),
                        HttpMethod.GET,
                        entity,
                        JsonNode.class
                );
                JsonNode issuesBodyPage = issuesResponsePage.getBody();
                if (issuesBodyPage == null) break;
                if (firstIssuesBody == null) firstIssuesBody = issuesBodyPage;
                if (totalIssues == 0) totalIssues = issuesBodyPage.path("total").asInt(0);
                JsonNode issuesPageArr = issuesBodyPage.path("issues");
                if (!issuesPageArr.isArray() || issuesPageArr.isEmpty()) break;
                for (JsonNode item : issuesPageArr) {
                    allIssues.add(item);
                }
                if (allIssues.size() >= totalIssues) break;
                pageIndex++;
                if (pageIndex > 50) break;
            }
            if (firstIssuesBody != null) {
                result.put("total_issues", totalIssues);
                result.put("issues", allIssues);
                result.put("issue_facets", firstIssuesBody.path("facets"));
            }
        } catch (Exception e) {
            log.warn("⚠️ Issues Sonar indisponibles (projectKey={}, branch={}): {}", pk, b, e.getMessage());
        }

        // 3) Hotspots
        try {
            MultiValueMap<String, String> hotspotParams = new LinkedMultiValueMap<>();
            hotspotParams.add("projectKey", pk);
            hotspotParams.add("branch", b);
            hotspotParams.add("ps", "100");
            ResponseEntity<JsonNode> hotspotsResponse = restTemplate.exchange(
                    buildSonarUri("/api/hotspots/search", hotspotParams),
                    HttpMethod.GET, entity, JsonNode.class);
            if (hotspotsResponse.getBody() != null) {
                JsonNode hotspotsBody = hotspotsResponse.getBody();
                JsonNode hotspotsArray = hotspotsBody.path("hotspots");
                int totalFromApi = hotspotsBody.path("total").asInt(0);
                int count = hotspotsArray.isArray() ? hotspotsArray.size() : 0;
                result.put("total_hotspots", Math.max(totalFromApi, count));
                result.put("hotspots", hotspotsArray);
            }
        } catch (Exception e) {
            log.warn("⚠️ Hotspots Sonar indisponibles (projectKey={}, branch={}): {}", pk, b, e.getMessage());
        }

        // 4) Quality Gate par branche
        Map<String, Object> qg = fetchSonarQualityGateStatus(pk, b);
        if (!qg.isEmpty()) {
            result.put("quality_gate", qg);
        }

        mergeSonarMetricsFromQualityGate(result);
        enrichSonarMetricsFromIssueFacets(result);
        deriveRatingsFromOpenIssues(result);
        enrichSonarDerivedFromMeasures(result);

        // Fallback Software Quality uniquement si métriques SQ absentes (Sonar < 10)
        enrichSoftwareQualityFallbackIfMissing(result, pk, b);
        enrichSonarDerivedFromMeasures(result);
        attachSonarComponentTrees(result, pk, b);
        translateSonarListsInResult(result);

        return result;
    }

    /** Couverture et duplication par fichier (branch-aware). */
    private void attachSonarComponentTrees(Map<String, Object> result, String projectKey, String branch) {
        if (projectKey == null || projectKey.isBlank()) return;
        RestTemplate restTemplate = sonarRestTemplate;
        HttpEntity<String> entity = sonarAuthEntity();
        String pk = projectKey.trim();

        try {
            MultiValueMap<String, String> dupParams = new LinkedMultiValueMap<>();
            dupParams.add("component", pk);
            dupParams.add("metricKeys", "duplicated_lines_density");
            dupParams.add("qualifiers", "FIL");
            dupParams.add("ps", "100");
            if (branch != null && !branch.isBlank()) {
                dupParams.add("branch", branch.trim());
            }
            ResponseEntity<JsonNode> dupResponse = restTemplate.exchange(
                    buildSonarUri("/api/measures/component_tree", dupParams),
                    HttpMethod.GET, entity, JsonNode.class);
            if (dupResponse.getBody() != null) {
                result.put("duplication_components", dupResponse.getBody().path("components"));
            }
        } catch (Exception e) {
            log.warn("⚠️ Duplication par fichier indisponible (projectKey={}, branch={}): {}", projectKey, branch, e.getMessage());
        }

        try {
            MultiValueMap<String, String> covParams = new LinkedMultiValueMap<>();
            covParams.add("component", pk);
            covParams.add("metricKeys", "coverage,uncovered_lines,uncovered_conditions");
            covParams.add("qualifiers", "FIL");
            covParams.add("ps", "100");
            if (branch != null && !branch.isBlank()) {
                covParams.add("branch", branch.trim());
            }
            ResponseEntity<JsonNode> covResponse = restTemplate.exchange(
                    buildSonarUri("/api/measures/component_tree", covParams),
                    HttpMethod.GET, entity, JsonNode.class);
            if (covResponse.getBody() != null) {
                result.put("coverage_components", covResponse.getBody().path("components"));
            }
        } catch (Exception e) {
            log.warn("⚠️ Couverture par fichier indisponible (projectKey={}, branch={}): {}", projectKey, branch, e.getMessage());
        }
    }

    /**
     * Historique d'analyses + séries temporelles (Issues, Coverage, Duplications) — onglet Activité.
     */
    public Map<String, Object> getSonarActivityHistory(String projectKey, String branch) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (projectKey == null || projectKey.isBlank()) {
            return result;
        }
        String pk = projectKey.trim();
        String b = branch != null && !branch.isBlank() ? branch.trim() : "main";
        RestTemplate restTemplate = sonarRestTemplate;
        HttpEntity<String> entity = sonarAuthEntity();

        try {
            MultiValueMap<String, String> historyParams = new LinkedMultiValueMap<>();
            historyParams.add("component", pk);
            historyParams.add("metrics", "violations,coverage,duplicated_lines_density,ncloc,duplicated_lines,bugs,vulnerabilities,code_smells");
            historyParams.add("ps", "500");
            historyParams.add("branch", b);
            ResponseEntity<JsonNode> historyResponse = restTemplate.exchange(
                    buildSonarUri("/api/measures/search_history", historyParams),
                    HttpMethod.GET, entity, JsonNode.class);
            if (historyResponse.getBody() != null) {
                result.put("measure_history", objectMapper.convertValue(historyResponse.getBody().path("measures"), List.class));
            }
        } catch (Exception e) {
            log.warn("⚠️ Historique métriques Sonar indisponible: {}", e.getMessage());
        }

        try {
            MultiValueMap<String, String> analysesParams = new LinkedMultiValueMap<>();
            analysesParams.add("project", pk);
            analysesParams.add("ps", "50");
            analysesParams.add("branch", b);
            ResponseEntity<JsonNode> analysesResponse = restTemplate.exchange(
                    buildSonarUri("/api/project_analyses/search", analysesParams),
                    HttpMethod.GET, entity, JsonNode.class);
            if (analysesResponse.getBody() != null) {
                result.put("analyses", objectMapper.convertValue(analysesResponse.getBody().path("analyses"), List.class));
            }
        } catch (Exception e) {
            log.warn("⚠️ Historique analyses Sonar indisponible: {}", e.getMessage());
        }

        result.put("branch", b);
        result.put("sonar_project_key", pk);
        return result;
    }

    /**
     * Détail d'une issue : métadonnées, règle, extrait de code (comme Security Hotspots).
     */
    public Map<String, Object> getIssueDetails(String issueKey) {
        return getIssueDetails(issueKey, null);
    }

    public Map<String, Object> getIssueDetails(String issueKey, String branch) {
        if (issueKey == null || issueKey.isBlank()) {
            throw new IllegalArgumentException("issueKey requis");
        }
        try {
            RestTemplate restTemplate = sonarRestTemplate;
            HttpEntity<String> entity = sonarAuthEntity();

            MultiValueMap<String, String> searchParams = new LinkedMultiValueMap<>();
            searchParams.add("issues", issueKey.trim());
            searchParams.add("additionalFields", "_all,rules");
            ResponseEntity<JsonNode> searchResponse = restTemplate.exchange(
                    buildSonarUri("/api/issues/search", searchParams),
                    HttpMethod.GET, entity, JsonNode.class);
            JsonNode body = searchResponse.getBody();
            if (body == null || !body.path("issues").isArray() || body.path("issues").isEmpty()) {
                throw new RuntimeException("Issue non trouvée: " + issueKey);
            }
            JsonNode issue = body.path("issues").get(0);
            String ruleKey = issue.path("rule").asText(null);
            String resolvedBranch = (branch != null && !branch.isBlank())
                    ? branch.trim()
                    : issue.path("branch").asText(null);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("issue", objectMapper.convertValue(issue, Map.class));
            result.put("branch", resolvedBranch);

            // Toujours préférer rules/show (sections complètes) — issues/search ne renvoie qu'un résumé
            if (ruleKey != null && !ruleKey.isBlank()) {
                try {
                    MultiValueMap<String, String> ruleParams = new LinkedMultiValueMap<>();
                    ruleParams.add("key", ruleKey);
                    ruleParams.add("actives", "true");
                    if (resolvedBranch != null && !resolvedBranch.isBlank()) {
                        ruleParams.add("branch", resolvedBranch);
                    }
                    addSonarRuleLocaleParams(ruleParams);
                    ResponseEntity<JsonNode> ruleResponse = restTemplate.exchange(
                            buildSonarUri("/api/rules/show", ruleParams),
                            HttpMethod.GET, entity, JsonNode.class);
                    if (ruleResponse.getBody() != null) {
                        JsonNode rootRule = ruleResponse.getBody();
                        JsonNode rule = rootRule.has("rule") ? rootRule.get("rule") : rootRule;
                        result.put("rule", objectMapper.convertValue(rule, Map.class));
                    }
                } catch (Exception e) {
                    log.warn("Règle issue non récupérée pour {}: {}", ruleKey, e.getMessage());
                }
            }

            if (!result.containsKey("rule") && body.path("rules").isArray() && ruleKey != null) {
                for (JsonNode r : body.path("rules")) {
                    if (ruleKey.equals(r.path("key").asText(null))) {
                        result.put("rule", objectMapper.convertValue(r, Map.class));
                        break;
                    }
                }
            }

            Object ruleObj = result.get("rule");
            if (ruleObj instanceof Map<?, ?> ruleMap) {
                translateSonarRuleMapToFrench((Map<String, Object>) ruleMap, ruleKey);
            }
            translateSonarIssueMessage(result, ruleKey);

            String componentKey = issue.path("component").asText(null);
            int line = issue.path("line").asInt(0);
            if (line <= 0 && issue.has("textRange")) {
                line = issue.path("textRange").path("startLine").asInt(0);
            }
            if (componentKey != null && line > 0) {
                attachSonarSourceSnippet(result, restTemplate, entity, componentKey, line, resolvedBranch);
            }

            result.put("sonar_host_url", normalizeSonarHostUrl());
            result.put("sonar_project_key", sonarProjectKey);
            return result;
        } catch (Exception e) {
            log.error("❌ Erreur détail issue {}: {}", issueKey, e.getMessage());
            throw new RuntimeException("Impossible de récupérer le détail de l'issue", e);
        }
    }

    private void attachSonarSourceSnippet(
            Map<String, Object> result,
            RestTemplate restTemplate,
            HttpEntity<String> entity,
            String componentKey,
            int line,
            String branch
    ) {
        try {
            MultiValueMap<String, String> rawParams = new LinkedMultiValueMap<>();
            rawParams.add("key", componentKey);
            if (branch != null && !branch.isBlank()) {
                rawParams.add("branch", branch.trim());
            }
            ResponseEntity<String> rawResponse = restTemplate.exchange(
                    buildSonarUri("/api/sources/raw", rawParams),
                    HttpMethod.GET, entity, String.class);
            if (rawResponse.getBody() != null && !rawResponse.getBody().isBlank()) {
                String[] lines = rawResponse.getBody().split("\r?\n");
                int from = Math.max(0, line - 6);
                int to = Math.min(lines.length, line + 5);
                List<String> snippet = new ArrayList<>();
                for (int i = from; i < to; i++) {
                    snippet.add(lines[i]);
                }
                result.put("sourceLines", snippet);
                result.put("sourceLineFrom", from + 1);
                result.put("highlightLine", line);
                return;
            }
        } catch (Exception e) {
            log.warn("sources/raw issue {}: {}", componentKey, e.getMessage());
        }

        try {
            int from = Math.max(1, line - 6);
            int to = line + 5;
            MultiValueMap<String, String> linesParams = new LinkedMultiValueMap<>();
            linesParams.add("key", componentKey);
            linesParams.add("from", String.valueOf(from));
            linesParams.add("to", String.valueOf(to));
            if (branch != null && !branch.isBlank()) {
                linesParams.add("branch", branch.trim());
            }
            ResponseEntity<JsonNode> linesResponse = restTemplate.exchange(
                    buildSonarUri("/api/sources/lines", linesParams),
                    HttpMethod.GET, entity, JsonNode.class);
            JsonNode linesBody = linesResponse.getBody();
            if (linesBody != null && linesBody.isArray() && !linesBody.isEmpty()) {
                List<String> snippet = new ArrayList<>();
                List<Integer> lineNumbers = new ArrayList<>();
                for (JsonNode ln : linesBody) {
                    lineNumbers.add(ln.path("line").asInt());
                    snippet.add(ln.path("code").asText(""));
                }
                result.put("sourceLines", snippet);
                result.put("sourceLineNumbers", lineNumbers);
                result.put("sourceLineFrom", from);
                result.put("highlightLine", line);
            }
        } catch (Exception ex) {
            log.warn("sources/lines issue {}: {}", componentKey, ex.getMessage());
        }
    }

    /**
     * Phase B — dérive by_severity (violations) et Software Quality depuis measures/component uniquement.
     * Ne pas utiliser issues/search pour H/M/L Software Quality.
     */
    @SuppressWarnings("unchecked")
    public void enrichSonarDerivedFromMeasures(Map<String, Object> result) {
        if (result == null) return;
        Map<String, Object> metrics = getOrCreateSonarMetrics(result);

        Map<String, Integer> bySeverity = new LinkedHashMap<>();
        bySeverity.put("blocker", parseIntSafe(metrics.get("blocker_violations")));
        bySeverity.put("critical", parseIntSafe(metrics.get("critical_violations")));
        bySeverity.put("major", parseIntSafe(metrics.get("major_violations")));
        bySeverity.put("minor", parseIntSafe(metrics.get("minor_violations")));
        bySeverity.put("info", parseIntSafe(metrics.get("info_violations")));
        if (bySeverity.values().stream().anyMatch(v -> v > 0)) {
            metrics.put("by_severity", bySeverity);
            result.put("open_issues_by_severity", bySeverity);
            int open = bySeverity.values().stream().mapToInt(Integer::intValue).sum();
            metrics.put("open_issues", open);
            result.put("open_issues", open);
        }

        Map<String, Integer> sqGlobalSeverity = new LinkedHashMap<>();
        sqGlobalSeverity.put("high", parseIntSafe(metrics.get("software_quality_high_severity_issues")));
        sqGlobalSeverity.put("medium", parseIntSafe(metrics.get("software_quality_medium_severity_issues")));
        sqGlobalSeverity.put("low", parseIntSafe(metrics.get("software_quality_low_severity_issues")));
        if (sqGlobalSeverity.values().stream().anyMatch(v -> v > 0)) {
            metrics.put("software_quality_severity", sqGlobalSeverity);
            result.put("software_quality_severity", sqGlobalSeverity);
        }

        putSonarRatingLetter(metrics, "security_rating");
        putSonarRatingLetter(metrics, "reliability_rating");
        putSonarRatingLetter(metrics, "sqale_rating");
        putSonarRatingLetter(metrics, "software_quality_security_rating");
        putSonarRatingLetter(metrics, "software_quality_reliability_rating");
        putSonarRatingLetter(metrics, "software_quality_maintainability_rating");

        aliasSonarRatingMetric(metrics, "software_quality_security_rating", "security_rating");
        aliasSonarRatingMetric(metrics, "software_quality_reliability_rating", "reliability_rating");
        aliasSonarRatingMetric(metrics, "software_quality_maintainability_rating", "maintainability_rating");
        aliasSonarRatingMetric(metrics, "software_quality_maintainability_rating", "sqale_rating");

        if (metrics.containsKey("sqale_rating") && !metrics.containsKey("maintainability_rating")) {
            metrics.put("maintainability_rating", metrics.get("sqale_rating"));
        }
        if (metrics.containsKey("sqale_rating_letter") && !metrics.containsKey("maintainability_rating_letter")) {
            metrics.put("maintainability_rating_letter", metrics.get("sqale_rating_letter"));
        }

        List<Map<String, Object>> sqDimensions = buildSoftwareQualityFromMeasures(metrics);
        if (!sqDimensions.isEmpty()) {
            result.put("software_quality_dimensions", sqDimensions);
            metrics.put("software_quality_dimensions", sqDimensions);
        }
    }

    private void putSonarRatingLetter(Map<String, Object> metrics, String ratingKey) {
        Object raw = metrics.get(ratingKey);
        if (raw == null) return;
        String letter = sonarRatingToLetter(raw);
        if (letter != null) {
            metrics.put(ratingKey + "_letter", letter);
        }
    }

    /** Copie rating (+ lettre) Sonar 10+ vers clés legacy attendues par le front. */
    private void aliasSonarRatingMetric(Map<String, Object> metrics, String sourceKey, String targetKey) {
        if (metrics.get(sourceKey) == null) return;
        if (metrics.get(targetKey) == null) {
            metrics.put(targetKey, metrics.get(sourceKey));
        }
        String sourceLetter = sourceKey + "_letter";
        String targetLetter = targetKey + "_letter";
        if (metrics.get(sourceLetter) != null && metrics.get(targetLetter) == null) {
            metrics.put(targetLetter, metrics.get(sourceLetter));
        }
    }

    private String sonarRatingToLetter(Object ratingValue) {
        if (ratingValue == null) return null;
        String s = String.valueOf(ratingValue).trim().toUpperCase(Locale.ROOT);
        if (s.length() == 1 && s.charAt(0) >= 'A' && s.charAt(0) <= 'E') {
            return s;
        }
        try {
            int n = (int) Math.round(Double.parseDouble(s));
            return switch (n) {
                case 1 -> "A";
                case 2 -> "B";
                case 3 -> "C";
                case 4 -> "D";
                case 5 -> "E";
                default -> null;
            };
        } catch (Exception e) {
            return null;
        }
    }

    private List<Map<String, Object>> buildSoftwareQualityFromMeasures(Map<String, Object> metrics) {
        List<Map<String, Object>> dims = new ArrayList<>();
        dims.add(softwareQualityDimFromMeasures(metrics, "SECURITY",
                "software_quality_security_issues", "software_quality_security_rating",
                "software_quality_security_high_issues", "software_quality_security_medium_issues",
                "software_quality_security_low_issues", "security_rating"));
        dims.add(softwareQualityDimFromMeasures(metrics, "RELIABILITY",
                "software_quality_reliability_issues", "software_quality_reliability_rating",
                "software_quality_reliability_high_issues", "software_quality_reliability_medium_issues",
                "software_quality_reliability_low_issues", "reliability_rating"));
        dims.add(softwareQualityDimFromMeasures(metrics, "MAINTAINABILITY",
                "software_quality_maintainability_issues", "software_quality_maintainability_rating",
                "software_quality_maintainability_high_issues", "software_quality_maintainability_medium_issues",
                "software_quality_maintainability_low_issues", "sqale_rating"));
        return dims.stream()
                .filter(d -> intValMap(d, "issues") > 0 || d.get("rating") != null)
                .toList();
    }

    private Map<String, Object> softwareQualityDimFromMeasures(
            Map<String, Object> metrics,
            String dimension,
            String issuesKey,
            String ratingKey,
            String highKey,
            String mediumKey,
            String lowKey,
            String legacyRatingKey
    ) {
        Map<String, Object> dim = new LinkedHashMap<>();
        dim.put("dimension", dimension);
        dim.put("issues", parseIntSafe(metrics.get(issuesKey)));

        Object ratingRaw = metrics.get(ratingKey);
        if (ratingRaw == null) {
            ratingRaw = metrics.get(legacyRatingKey);
        }
        String letter = sonarRatingToLetter(ratingRaw);
        if (letter != null) {
            dim.put("rating", letter);
            dim.put("ratingValue", sonarRatingNumeric(ratingRaw));
        }

        int high = parseIntSafe(metrics.get(highKey));
        int medium = parseIntSafe(metrics.get(mediumKey));
        int low = parseIntSafe(metrics.get(lowKey));
        if (high > 0 || medium > 0 || low > 0) {
            Map<String, Integer> bySev = new LinkedHashMap<>();
            bySev.put("high", high);
            bySev.put("medium", medium);
            bySev.put("low", low);
            dim.put("bySeverity", bySev);
        }
        return dim;
    }

    private static int intValMap(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (v instanceof Number n) return n.intValue();
        try {
            return v != null ? Integer.parseInt(String.valueOf(v)) : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    private int sonarRatingNumeric(Object ratingValue) {
        String letter = sonarRatingToLetter(ratingValue);
        if (letter == null) return 0;
        return switch (letter) {
            case "A" -> 1;
            case "B" -> 2;
            case "C" -> 3;
            case "D" -> 4;
            case "E" -> 5;
            default -> 0;
        };
    }

    /**
     * Fallback Sonar &lt; 10 : compte issues ouvertes par dimension via issues/search.
     * N'alimente pas bySeverity H/M/L (réservé aux métriques SQ dédiées).
     */
    private void enrichSoftwareQualityFallbackIfMissing(Map<String, Object> result, String projectKey, String branch) {
        Map<String, Object> metrics = getOrCreateSonarMetrics(result);
        if (hasSoftwareQualityIssueMetrics(metrics)) {
            return;
        }
        for (String quality : List.of("SECURITY", "RELIABILITY", "MAINTAINABILITY")) {
            String key = switch (quality) {
                case "SECURITY" -> "software_quality_security_issues";
                case "RELIABILITY" -> "software_quality_reliability_issues";
                default -> "software_quality_maintainability_issues";
            };
            int total = fetchSonarOpenIssueTotal(projectKey, branch, quality);
            if (total > 0) {
                putSonarMetricIfAbsent(metrics, key, total);
            }
        }
    }

    private boolean hasSoftwareQualityIssueMetrics(Map<String, Object> metrics) {
        return parseIntSafe(metrics.get("software_quality_security_issues")) > 0
                || parseIntSafe(metrics.get("software_quality_reliability_issues")) > 0
                || parseIntSafe(metrics.get("software_quality_maintainability_issues")) > 0
                || metrics.containsKey("software_quality_security_rating");
    }

    private int fetchSonarOpenIssueTotal(String projectKey, String branch, String softwareQuality) {
        try {
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("componentKeys", projectKey);
            params.add("statuses", "OPEN,CONFIRMED,REOPENED");
            params.add("ps", "1");
            params.add("branch", branch);
            params.add("impactSoftwareQualities", softwareQuality);
            RestTemplate restTemplate = sonarRestTemplate;
            ResponseEntity<JsonNode> response = restTemplate.exchange(
                    buildSonarUri("/api/issues/search", params),
                    HttpMethod.GET, sonarAuthEntity(), JsonNode.class);
            return response.getBody() != null ? response.getBody().path("total").asInt(0) : 0;
        } catch (Exception e) {
            log.debug("Sonar SQ fallback count {} (branch={}): {}", softwareQuality, branch, e.getMessage());
            return 0;
        }
    }

    /**
     * Récupère le statut du Quality Gate global (ou par branche si fournie).
     */
    public Map<String, Object> getQualityGateStatus() {
        return getQualityGateStatus(null);
    }

    public Map<String, Object> getQualityGateStatus(String branch) {
        Map<String, Object> qg = fetchSonarQualityGateStatus(sonarProjectKey, branch);
        if (qg.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, Object> result = new LinkedHashMap<>(qg);
        result.put("conditions", qg.get("conditions"));
        return result;
    }

    /**
     * Récupère le code source brut et les métadonnées de duplication SonarQube pour un composant (fichier).
     */
    public Map<String, Object> getSonarFileDuplications(String componentKey) {
        try {
            RestTemplate restTemplate = sonarRestTemplate;
            HttpEntity<String> entity = sonarAuthEntity();

            MultiValueMap<String, String> srcParams = new LinkedMultiValueMap<>();
            srcParams.add("key", componentKey);
            ResponseEntity<String> srcResponse = restTemplate.exchange(
                    buildSonarUri("/api/sources/raw", srcParams),
                    HttpMethod.GET,
                    entity,
                    String.class
            );

            MultiValueMap<String, String> dupParams = new LinkedMultiValueMap<>();
            dupParams.add("key", componentKey);
            ResponseEntity<JsonNode> dupResponse = restTemplate.exchange(
                    buildSonarUri("/api/duplications/show", dupParams),
                    HttpMethod.GET,
                    entity,
                    JsonNode.class
            );

            Map<String, Object> result = new HashMap<>();
            result.put("componentKey", componentKey);
            result.put("source", srcResponse.getBody() != null ? srcResponse.getBody() : "");
            result.put("duplications", dupResponse.getBody());
            return result;
        } catch (Exception e) {
            log.error("❌ Erreur récupération duplications SonarQube pour {}: {}", componentKey, e.getMessage());
            throw new RuntimeException("Impossible de récupérer les duplications pour " + componentKey, e);
        }
    }

    /**
     * Récupère tous les détails d'un Security Hotspot : hotspot (show), règle (risk/fix), extrait de code.
     */
    /**
     * Récupère tous les détails d'un Security Hotspot : hotspot (show), règle (risk/fix), extrait de code.
     */
    public Map<String, Object> getHotspotDetails(String hotspotKey) {
        try {
            RestTemplate restTemplate = sonarRestTemplate;
            HttpEntity<String> entity = sonarAuthEntity();

            MultiValueMap<String, String> showParams = new LinkedMultiValueMap<>();
            showParams.add("hotspot", hotspotKey);
            ResponseEntity<JsonNode> showResponse = restTemplate.exchange(
                    buildSonarUri("/api/hotspots/show", showParams),
                    HttpMethod.GET, entity, JsonNode.class);
            if (showResponse.getBody() == null || !showResponse.getBody().has("key")) {
                throw new RuntimeException("Hotspot non trouvé: " + hotspotKey);
            }
            JsonNode hotspot = showResponse.getBody();
            String ruleKey = hotspot.has("ruleKey") ? hotspot.get("ruleKey").asText() : null;
            String hotspotBranch = hotspot.path("branch").asText(null);

            log.info("🔍 Hotspot récupéré (key={}): {}", hotspotKey, hotspot);
            log.info("🔍 Hotspot - ruleKey={}, component={}", ruleKey, hotspot.path("component"));

            Map<String, Object> result = new HashMap<>();
            result.put("hotspot", objectMapper.convertValue(hotspot, Map.class));

            if (ruleKey != null) {
                try {
                    MultiValueMap<String, String> ruleParams = new LinkedMultiValueMap<>();
                    ruleParams.add("key", ruleKey);
                    ruleParams.add("actives", "true");
                    if (hotspotBranch != null && !hotspotBranch.isBlank()) {
                        ruleParams.add("branch", hotspotBranch);
                    }
                    addSonarRuleLocaleParams(ruleParams);
                    ResponseEntity<JsonNode> ruleResponse = restTemplate.exchange(
                            buildSonarUri("/api/rules/show", ruleParams),
                            HttpMethod.GET, entity, JsonNode.class);

                    if (ruleResponse.getBody() != null) {
                        JsonNode rootRule = ruleResponse.getBody();
                        JsonNode rule = rootRule.has("rule") ? rootRule.get("rule") : rootRule;
                        log.info("📋 Règle brute pour hotspot {} (ruleKey={}): {}", hotspotKey, ruleKey, rule);
                        result.put("rule", objectMapper.convertValue(rule, Map.class));
                    } else {
                        log.warn("❓ Réponse vide de /api/rules/show pour ruleKey={}", ruleKey);
                    }
                } catch (Exception e) {
                    log.warn("Règle non récupérée pour {}: {}", ruleKey, e.getMessage());
                }
            }

            Object ruleObj = result.get("rule");
            if (ruleObj instanceof Map<?, ?> ruleMap) {
                translateSonarRuleMapToFrench((Map<String, Object>) ruleMap, ruleKey);
            } else {
                Object hotspotObj = result.get("hotspot");
                if (hotspotObj instanceof Map<?, ?> hotspotMap && hotspotMap.get("rule") instanceof Map<?, ?> embedded) {
                    Map<String, Object> embeddedRule = (Map<String, Object>) embedded;
                    translateSonarRuleMapToFrench(embeddedRule, ruleKey);
                    result.put("rule", embeddedRule);
                }
            }
            syncTranslatedHotspotRule(result);
            translateSonarHotspotMessage(result, ruleKey);

            String componentKey = null;
            JsonNode compNode = hotspot.get("component");
            if (compNode != null && !compNode.isMissingNode()) {
                if (compNode.isTextual()) {
                    componentKey = compNode.asText();
                } else if (compNode.has("key")) {
                    componentKey = compNode.get("key").asText();
                } else if (compNode.has("path")) {
                    componentKey = compNode.get("path").asText();
                }
            }

            int line = hotspot.has("line") ? hotspot.path("line").asInt(0) : 0;

            if (componentKey != null && line > 0) {
                attachSonarSourceSnippet(result, restTemplate, entity, componentKey, line, hotspotBranch);
            }

            result.put("sonar_host_url", normalizeSonarHostUrl());
            result.put("sonar_project_key", sonarProjectKey);
            log.info("✅ Détail hotspot récupéré: {}", hotspotKey);
            return result;

        } catch (Exception e) {
            log.error("❌ Erreur récupération détail hotspot {}: {}", hotspotKey, e.getMessage());
            throw new RuntimeException("Impossible de récupérer le détail du hotspot", e);
        }
    }
    // ============================================
    // PIPELINE - GESTION AVANCÉE
    // ============================================

    /**
     * Attend qu'un pipeline se termine (avec timeout)
     *
     * @param pipelineId ID du pipeline
     * @param timeoutMinutes Timeout en minutes
     * @return Pipeline terminé
     */
    public Pipeline waitForPipelineCompletion(Long pipelineId, int timeoutMinutes) {
        try {
            long startTime = System.currentTimeMillis();
            long timeoutMillis = timeoutMinutes * 60 * 1000L;

            log.info("⏳ Attente de la fin du pipeline {} (timeout: {}min)", pipelineId, timeoutMinutes);

            while (!isPipelineFinished(pipelineId)) {
                // Vérifier timeout
                if (System.currentTimeMillis() - startTime > timeoutMillis) {
                    log.error("⏰ Timeout : Pipeline {} non terminé après {} minutes",
                            pipelineId, timeoutMinutes);
                    throw new RuntimeException(
                            String.format("Timeout : Pipeline non terminé après %d minutes", timeoutMinutes)
                    );
                }

                // Attendre 5 secondes avant de revérifier
                Thread.sleep(5000);

                PipelineStatus currentStatus = getPipelineStatus(pipelineId);
                log.debug("⏳ Pipeline {} - Statut actuel: {}", pipelineId, currentStatus);
            }

            // Pipeline terminé, récupérer le statut final
            Pipeline pipeline = getPipeline(pipelineId);

            log.info("✅ Pipeline {} terminé avec statut: {} - Durée: {}s",
                    pipelineId, pipeline.getStatus(), pipeline.getDuration());
            return pipeline;

        } catch (InterruptedException e) {
            log.error("❌ Interruption lors de l'attente du pipeline {}", pipelineId);
            Thread.currentThread().interrupt();
            throw new RuntimeException("Attente du pipeline interrompue", e);
        } catch (Exception e) {
            log.error("❌ Erreur lors de l'attente du pipeline {}: {}", pipelineId, e.getMessage());
            throw new RuntimeException("Erreur attente pipeline", e);
        }
    }

    /**
     * Annule un pipeline en cours
     *
     * @param pipelineId ID du pipeline à annuler
     */
    public void cancelPipeline(Long pipelineId) {
        try {
            log.info("🛑 Annulation du pipeline {}", pipelineId);

            gitLabApi.getPipelineApi().cancelPipelineJobs(gitlabProjectId, pipelineId);

            log.info("✅ Pipeline {} annulé avec succès", pipelineId);

        } catch (GitLabApiException e) {
            log.error("❌ Erreur annulation pipeline {}: {}", pipelineId, e.getMessage());
            throw new RuntimeException("Impossible d'annuler le pipeline", e);
        }
    }

    /**
     * Relance un pipeline échoué
     *
     * @param pipelineId ID du pipeline à relancer
     * @return Nouveau pipeline créé
     */
    public Pipeline retryPipeline(Long pipelineId) {
        try {
            log.info("🔄 Relance du pipeline {}", pipelineId);

            Pipeline retryPipeline = gitLabApi.getPipelineApi()
                    .retryPipelineJob(gitlabProjectId, pipelineId);

            log.info("✅ Pipeline {} relancé - Nouveau ID: {}", pipelineId, retryPipeline.getId());
            return retryPipeline;

        } catch (GitLabApiException e) {
            log.error("❌ Erreur relance pipeline {}: {}", pipelineId, e.getMessage());
            throw new RuntimeException("Impossible de relancer le pipeline", e);
        }
    }

    /**
     * Relance un job GitLab (retry) sans relancer tout le pipeline.
     *
     * @param jobId ID du job
     */
    public void retryJob(Long jobId) {
        try {
            log.info("🔁 Retry job {}", jobId);
            gitLabApi.getJobApi().retryJob(gitlabProjectId, jobId);
        } catch (GitLabApiException e) {
            log.error("❌ Erreur retry job {}: {}", jobId, e.getMessage());
            throw new RuntimeException("Impossible de relancer le job", e);
        }
    }

    // ============================================
    // UTILITAIRES
    // ============================================

    /**
     * Récupère les variables d'un pipeline
     *
     * @param pipelineId ID du pipeline
     * @return Liste des variables
     */
    public List<Variable> getPipelineVariables(Long pipelineId) {
        try {
            Pipeline pipeline = getPipeline(pipelineId);

            // Les variables ne sont pas toujours disponibles via l'API
            // Cette méthode peut retourner une liste vide
            log.info("🔍 Récupération variables du pipeline {}", pipelineId);

            return new ArrayList<>(); // GitLab4J ne fournit pas directement les variables du pipeline

        } catch (Exception e) {
            log.error("❌ Erreur récupération variables: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Récupère le résumé d'un pipeline (pour affichage)
     *
     * @param pipelineId ID du pipeline
     * @return Map avec les informations essentielles
     */
    @Cacheable(value = "pipelineSummaries", key = "#pipelineId", unless = "#result == null")
    public Map<String, Object> getPipelineSummary(Long pipelineId) {
        try {
            // Version avec timeout et exécution parallèle
            CompletableFuture<Pipeline> pipelineFuture = CompletableFuture.supplyAsync(() -> {
                try {
                    return gitLabApi.getPipelineApi().getPipeline(gitlabProjectId, pipelineId);
                } catch (GitLabApiException e) {
                    throw new RuntimeException(e);
                }
            });

            CompletableFuture<List<Job>> jobsFuture = CompletableFuture.supplyAsync(() -> {
                try {
                    return gitLabApi.getJobApi().getJobsForPipeline(gitlabProjectId, pipelineId);
                } catch (GitLabApiException e) {
                    throw new RuntimeException(e);
                }
            });

            // Timeout de 3 secondes
            Pipeline pipeline = pipelineFuture.get(gitlabTimeoutSeconds, TimeUnit.SECONDS);
            List<Job> jobs = jobsFuture.get(gitlabTimeoutSeconds, TimeUnit.SECONDS);

            return buildPipelineSummary(pipeline, jobs);

        } catch (Exception e) {
            log.warn("⚠️ Timeout ou erreur GitLab pour pipeline {}, utilisation fallback DB", pipelineId);
            // Retourner les infos minimales depuis la base de données
            return getFallbackSummary(pipelineId);
        }
    }

    /**
     * Construit le résumé à partir des données GitLab
     */
    private Map<String, Object> buildPipelineSummary(Pipeline pipeline, List<Job> jobs) {
        Map<String, Object> summary = new HashMap<>();
        summary.put("id", pipeline.getId());
        summary.put("status", pipeline.getStatus().toString());
        summary.put("webUrl", pipeline.getWebUrl());
        summary.put("duration", pipeline.getDuration());
        summary.put("createdAt", pipeline.getCreatedAt());
        summary.put("finishedAt", pipeline.getFinishedAt());

        String sha = pipeline.getSha();
        summary.put("ref", pipeline.getRef());
        summary.put("sha", sha);
        summary.put("shortSha", sha != null && !sha.isEmpty() ? sha.substring(0, Math.min(8, sha.length())) : null);

        // Compter les jobs par statut
        Map<String, Long> jobStatusCount = new HashMap<>();
        for (Job job : jobs) {
            String status = job.getStatus().toString();
            jobStatusCount.put(status, jobStatusCount.getOrDefault(status, 0L) + 1);
        }
        summary.put("jobStatusCount", jobStatusCount);
        summary.put("totalJobs", jobs.size());

        // Liste des jobs
        List<Map<String, Object>> jobsList = new ArrayList<>();
        for (Job job : jobs) {
            Map<String, Object> jobInfo = new HashMap<>();
            jobInfo.put("id", job.getId());
            jobInfo.put("name", job.getName());
            jobInfo.put("status", job.getStatus().toString());
            jobInfo.put("stage", job.getStage());
            jobInfo.put("duration", job.getDuration());
            jobInfo.put("webUrl", job.getWebUrl());
            jobsList.add(jobInfo);
        }
        summary.put("jobs", jobsList);

        log.info("✅ Résumé du pipeline {} généré", pipeline.getId());
        return summary;
    }
    private Map<String, Object> getFallbackSummary(Long pipelineId) {
        Map<String, Object> summary = new HashMap<>();
        summary.put("id", pipelineId);
        summary.put("status", "UNKNOWN");
        summary.put("webUrl", null);
        summary.put("duration", null);
        summary.put("createdAt", null);
        summary.put("finishedAt", null);
        summary.put("ref", null);
        summary.put("sha", null);
        summary.put("shortSha", null);
        summary.put("jobStatusCount", new HashMap<>());
        summary.put("totalJobs", 0);
        summary.put("jobs", List.of());
        return summary;
    }

    /**
     * Récupère tous les rapports de sécurité d'un pipeline
     *
     * @param pipelineId ID du pipeline
     * @return Map avec les rapports de sécurité parsés
     */
    public Map<String, JsonNode> getAllSecurityReports(Long pipelineId) {
        Map<String, JsonNode> reports = new HashMap<>();

        try {
            log.info("📊 Récupération de tous les rapports de sécurité du pipeline {}", pipelineId);

            List<Job> jobs = getPipelineJobs(pipelineId);

            // Rechercher les jobs de sécurité et récupérer leurs artifacts
            for (Job job : jobs) {
                String jobName = job.getName();

                // Job de scan des dépendances (Trivy)
                if (jobName.contains("dependency-scan") && job.getStatus() == JobStatus.SUCCESS) {
                    try {
                        JsonNode report = getSecurityReport(job.getId(), "trivy-dependencies-report.json");
                        reports.put("dependencies", report);
                        log.info("✅ Rapport de dépendances récupéré");
                    } catch (Exception e) {
                        log.warn("⚠️ Impossible de récupérer le rapport de dépendances: {}", e.getMessage());
                    }
                }

                // Job de scan de l'image (Trivy)
                if (jobName.contains("image-scan") && job.getStatus() == JobStatus.SUCCESS) {
                    try {
                        JsonNode report = getSecurityReport(job.getId(), "trivy-image-report.json");
                        reports.put("image", report);
                        log.info("✅ Rapport de l'image récupéré");
                    } catch (Exception e) {
                        log.warn("⚠️ Impossible de récupérer le rapport de l'image: {}", e.getMessage());
                    }
                }

                // Job SAST (SonarQube)
                if (jobName.contains("sast") && job.getStatus() == JobStatus.SUCCESS) {
                    try {
                        JsonNode report = getSecurityReport(job.getId(), "sonarqube-report.json");
                        reports.put("sast", report);
                        log.info("✅ Rapport SAST récupéré");
                    } catch (Exception e) {
                        log.warn("⚠️ Impossible de récupérer le rapport SAST: {}", e.getMessage());
                    }
                }
            }

            log.info("✅ {} rapports de sécurité récupérés au total", reports.size());
            return reports;

        } catch (Exception e) {
            log.error("❌ Erreur récupération rapports de sécurité: {}", e.getMessage());
            return reports; // Retourner ce qui a été récupéré
        }
    }

    // Dans GitLabService.java

    /**
     * Supprime un pipeline dans GitLab
     */
    public void deletePipeline(Long pipelineId) {
        try {
            gitLabApi.getPipelineApi().deletePipeline(gitlabProjectId, pipelineId);
            log.info("✅ Pipeline {} supprimé de GitLab", pipelineId);
        } catch (GitLabApiException e) {
            if (e.getHttpStatus() == 404) {
                log.warn("Pipeline {} déjà supprimé ou inexistant dans GitLab", pipelineId);
            } else {
                log.error("❌ Erreur suppression pipeline {} dans GitLab: {}", pipelineId, e.getMessage());
                throw new RuntimeException("Impossible de supprimer le pipeline dans GitLab", e);
            }
        }
    }
}