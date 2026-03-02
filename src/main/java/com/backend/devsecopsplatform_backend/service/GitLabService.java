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
import java.io.InputStream;
import java.util.*;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.scheduling.annotation.Async;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
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
    public Pipeline triggerPipeline(String gitRepoUrl, String branch, String envId, UUID applicationId, String dockerfilePath) {
        try {
            String githubToken = applicationService.getDecryptedGithubToken(applicationId);
            String gitBranch = branch != null && !branch.isBlank() ? branch : "main";
            String dockerPath = dockerfilePath != null && !dockerfilePath.isBlank() ? dockerfilePath : "./Dockerfile";

            log.info("📋 [Pipeline] Données envoyées au pipeline GitLab (amanibennaceur-group/EnviroTest, ref=master):");
            log.info("   GIT_REPO_URL={}", gitRepoUrl);
            log.info("   GIT_BRANCH={}", gitBranch);
            log.info("   ENVIRONMENT_ID={}", envId);
            log.info("   DOCKERFILE_PATH={}", dockerPath);
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
     * Récupère un job par son nom (ex: "sast-sonarqube", "dependency-scan-trivy")
     *
     * @param pipelineId ID du pipeline
     * @param jobName Nom du job
     * @return Job trouvé ou null
     */
    public Job getJobByName(Long pipelineId, String jobName) {
        List<Job> jobs = getPipelineJobs(pipelineId);

        return jobs.stream()
                .filter(job -> job.getName().equals(jobName))
                .findFirst()
                .orElse(null);
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
     * Utilise RestTemplate pour télécharger l'artefact .json du job (Trivy, SonarQube, etc.).
     * Essaie plusieurs chemins d'artefacts courants.
     *
     * @param jobId ID du job GitLab (ex: job de stage Scan)
     * @return Rapport de scan en JSON (JsonNode), ou null si aucun artefact trouvé
     */
    public JsonNode getScanResults(Long jobId) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set("PRIVATE-TOKEN", gitlabToken);

        // Chemins d'artefacts courants selon .gitlab-ci.yml (Trivy, SonarQube, rapport générique)
        String[] artifactPaths = {
                "report.json",
                "trivy-report.json",
                "trivy-dependencies-report.json",
                "gl-dependency-scanning-report.json",
                "gl-sast-report.json",
                "sonarqube-report.json",
                "scan-report.json"
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
                    log.info("✅ Scan results récupérés pour job {} (artefact: {})", jobId, path);
                    return report;
                }
            } catch (Exception e) {
                log.debug("Artefact {} non trouvé pour job {}: {}", path, jobId, e.getMessage());
            }
        }
        log.warn("⚠️ Aucun artefact JSON de scan trouvé pour le job {}", jobId);
        return null;
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
}