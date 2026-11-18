package com.backend.devsecopsplatform_backend.configuration;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateTimeDeserializer;
import org.gitlab4j.api.GitLabApi;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;

@Configuration
public class GitLabConfig {

    @Value("${gitlab.url}")
    private String gitlabUrl;

    @Value("${gitlab.token}")
    private String gitlabToken;

    @Bean
    public GitLabApi gitLabApi() {
        // Initialise la connexion à l'API GitLab, avec délais bornés (connexion 5 s, lecture 60 s) :
        // sans eux, un GitLab lent bloquait la requête HTTP et sa connexion PostgreSQL indéfiniment.
        GitLabApi api = new GitLabApi(gitlabUrl, gitlabToken);
        api.setRequestTimeout(5_000, 60_000);
        return api;
    }

    /**
     * ObjectMapper partagé — doit écrire Instant/LocalDateTime en ISO-8601
     * (pas en epoch secondes), sinon le front Angular date pipe / Date.parse casse
     * (affichage 1970 + chrono TTL vide).
     * <p>
     * Les LocalDateTime partent avec leur décalage (« 2026-11-18T09:50:36Z ») : sans lui, le navigateur
     * les lisait comme des heures locales et toutes les dates de la plateforme avaient une heure de retard
     * en Tunisie (la JVM et PostgreSQL sont en UTC). Voir {@link DisplayTime}.
     */
    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.registerModule(localDateTimeWithOffsetModule());
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return mapper;
    }

    /** Enregistré après JavaTimeModule : prioritaire pour LocalDateTime. */
    static SimpleModule localDateTimeWithOffsetModule() {
        SimpleModule module = new SimpleModule("LocalDateTimeWithOffset");
        module.addSerializer(LocalDateTime.class, new JsonSerializer<>() {
            @Override
            public void serialize(LocalDateTime value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
                gen.writeString(DisplayTime.iso(value));
            }
        });
        module.addDeserializer(LocalDateTime.class, new JsonDeserializer<>() {
            @Override
            public LocalDateTime deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                if (!p.hasToken(JsonToken.VALUE_STRING)) {
                    return LocalDateTimeDeserializer.INSTANCE.deserialize(p, ctxt);
                }
                String text = p.getText().trim();
                if (text.isEmpty()) {
                    return null;
                }
                try {
                    return LocalDateTime.parse(text);
                } catch (DateTimeParseException noOffset) {
                    // Instant envoyé par le navigateur (« …Z », « …+01:00 ») → heure de la JVM.
                    return OffsetDateTime.parse(text).atZoneSameInstant(DisplayTime.STORAGE_ZONE).toLocalDateTime();
                }
            }
        });
        return module;
    }
}
