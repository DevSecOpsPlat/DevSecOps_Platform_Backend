package com.backend.devsecopsplatform_backend.controller.appmgmt;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import java.util.UUID;

@Data
@Builder
public class EnvVarResponse {
    private UUID id;
    private String varKey;
    /** Valeur en clair si non-secret, sinon masquée (••••••). */
    private String varValue;
    @JsonProperty("isSecret")
    private boolean isSecret;
}
