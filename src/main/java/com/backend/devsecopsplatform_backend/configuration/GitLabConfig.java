package com.backend.devsecopsplatform_backend.configuration;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.gitlab4j.api.GitLabApi;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GitLabConfig {

    @Value("${gitlab.url}")
    private String gitlabUrl;

    @Value("${gitlab.token}")
    private String gitlabToken;

    @Bean
    public GitLabApi gitLabApi() {
        // Initialise la connexion à l'API GitLab
        return new GitLabApi(gitlabUrl, gitlabToken);
    }

    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        // Indispensable pour gérer les dates Java 8 (LocalDateTime) de tes entités
        mapper.registerModule(new JavaTimeModule());
        // Éviter les erreurs si le JSON contient des champs inconnus
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return mapper;
    }
}