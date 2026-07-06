package com.backend.devsecopsplatform_backend.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestTemplate;

/**
 * RestTemplate dédié aux appels SonarQube / SonarCloud.
 * Envoie {@code Accept-Language: fr} pour obtenir les descriptions de règles en français lorsque disponibles.
 */
@Configuration
public class SonarQubeConfig {

    @Bean
    public RestTemplate sonarRestTemplate(
            @Value("${sonarqube.accept-language:fr}") String acceptLanguage) {
        RestTemplate restTemplate = new RestTemplate();
        String lang = (acceptLanguage == null || acceptLanguage.isBlank()) ? "fr" : acceptLanguage.trim();
        restTemplate.getInterceptors().add((request, body, execution) -> {
            if (!request.getHeaders().containsKey(HttpHeaders.ACCEPT_LANGUAGE)) {
                request.getHeaders().add(HttpHeaders.ACCEPT_LANGUAGE, lang);
            }
            return execution.execute(request, body);
        });
        return restTemplate;
    }
}
