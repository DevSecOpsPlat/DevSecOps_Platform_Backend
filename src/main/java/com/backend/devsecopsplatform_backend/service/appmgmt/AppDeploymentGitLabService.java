package com.backend.devsecopsplatform_backend.service.appmgmt;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Déclenche le pipeline de déploiement GitLab (fourni séparément) via l'API GitLab.
 *
 * <p>Le pipeline n'est PAS écrit ici : on se contente de l'appeler comme le fait déjà
 * l'ancien flux (cf. {@code GitLabService.triggerPipeline}), en lui passant les variables
 * nécessaires (namespace, bundle de manifestes, configuration des services à builder…).</p>
 */
@Service
@Slf4j
public class AppDeploymentGitLabService {

    @Value("${gitlab.api-url}")
    private String gitlabApiUrl;

    @Value("${gitlab.token}")
    private String gitlabToken;

    /** Projet GitLab hébergeant le pipeline de déploiement (par défaut : même que le scan). */
    @Value("${deployment.pipeline.project-id:${gitlab.project-id}}")
    private Long deployProjectId;

    /** Branche du pipeline de déploiement. */
    @Value("${deployment.pipeline.ref:master}")
    private String deployRef;

    /**
     * Lance le pipeline de déploiement GitLab avec les variables fournies.
     *
     * @return l'identifiant du pipeline GitLab, ou {@code null} en cas d'échec réseau
     *         (le déploiement reste enregistré en base pour diagnostic).
     */
    public Long triggerPipeline(Map<String, String> variables) {
        try {
            List<Map<String, String>> variablesList = new ArrayList<>();
            variables.forEach((k, v) -> {
                Map<String, String> entry = new HashMap<>();
                entry.put("key", k);
                entry.put("value", v != null ? v : "");
                variablesList.add(entry);
            });

            Map<String, Object> body = new HashMap<>();
            body.put("ref", deployRef);
            body.put("variables", variablesList);

            String url = gitlabApiUrl + "/projects/" + deployProjectId + "/pipeline";
            RestTemplate rest = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("PRIVATE-TOKEN", gitlabToken);

            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);
            ResponseEntity<Map> response = rest.exchange(url, HttpMethod.POST, entity, Map.class);

            if (response.getStatusCode() != HttpStatus.OK && response.getStatusCode() != HttpStatus.CREATED) {
                throw new RuntimeException("GitLab API a répondu: " + response.getStatusCode());
            }
            Map<String, Object> res = response.getBody();
            if (res == null || res.get("id") == null) {
                throw new RuntimeException("Réponse GitLab vide");
            }
            Long pipelineId = ((Number) res.get("id")).longValue();
            log.info("✅ Pipeline de déploiement lancé - ID: {} - URL: {}", pipelineId, res.get("web_url"));
            return pipelineId;

        } catch (Exception e) {
            log.error("❌ Erreur déclenchement pipeline de déploiement: {}", e.getMessage());
            return null;
        }
    }
}
