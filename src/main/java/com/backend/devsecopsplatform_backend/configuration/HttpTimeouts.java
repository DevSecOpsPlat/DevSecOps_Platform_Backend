package com.backend.devsecopsplatform_backend.configuration;

import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

/**
 * Clients HTTP à délais bornés pour les outils externes (GitLab, GitHub).
 * Un {@code new RestTemplate()} n'a aucun délai : si l'outil ne répond pas, la requête attend
 * le délai TCP du système (~2 min) en gardant sa connexion PostgreSQL (open-in-view),
 * ce qui saturait le pool et ralentissait toute la plateforme.
 */
public final class HttpTimeouts {

    /** Connexion 5 s, lecture 60 s : suffisant pour l'API GitLab et le téléchargement d'artefacts. */
    public static final int CONNECT_MS = 5_000;
    public static final int READ_MS = 60_000;

    private HttpTimeouts() {
    }

    public static RestTemplate restTemplate() {
        return restTemplate(CONNECT_MS, READ_MS);
    }

    public static RestTemplate restTemplate(int connectMs, int readMs) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(connectMs);
        factory.setReadTimeout(readMs);
        return new RestTemplate(factory);
    }
}
