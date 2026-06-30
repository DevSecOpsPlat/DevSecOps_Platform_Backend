package com.backend.devsecopsplatform_backend.configuration;

import com.backend.devsecopsplatform_backend.service.defectdojo.DefectDojoHttpClientFactory;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.List;

/**
 * Vérifie au démarrage que le backend peut joindre l'API DefectDojo (indépendamment du pipeline GitLab).
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class DefectDojoStartupProbe {

    private final DefectDojoProperties properties;
    private final DefectDojoHttpClientFactory httpClientFactory;

    @EventListener(ApplicationReadyEvent.class)
    public void probeOnStartup() {
        if (!properties.isConfigured()) {
            log.info("DefectDojo : non configuré (DEFECTDOJO_URL / DEFECTDOJO_TOKEN vides)");
            return;
        }
        String base = properties.normalizedBaseUrl();
        log.info("DefectDojo : test connexion API → {} (host={})", base, properties.hostForLog());
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            headers.set("Authorization", properties.authorizationHeaderValue());
            if (base.contains("ngrok") || base.contains("trycloudflare.com")) {
                headers.set("Ngrok-Skip-Browser-Warning", "true");
            }
            RestTemplate rest = httpClientFactory.create(properties.isInsecureSsl());
            ResponseEntity<JsonNode> resp = rest.exchange(
                    base + "/api/v2/products/?limit=1",
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    JsonNode.class
            );
            if (resp.getStatusCode().is2xxSuccessful()) {
                log.info("DefectDojo : API joignable ✓");
            } else {
                log.warn("DefectDojo : API réponse {}", resp.getStatusCode());
            }
        } catch (Exception e) {
            log.warn("DefectDojo : API injoignable depuis le backend — {}. "
                            + "Le pipeline GitLab peut fonctionner avec une autre URL. "
                            + "Alignez DEFECTDOJO_URL backend sur GitLab CI (tunnel Cloudflare https://...). "
                            + "Erreur SSL « Bad authority » = hostname/certificat ne correspond pas à l'URL.",
                    e.getMessage());
        }
    }
}
