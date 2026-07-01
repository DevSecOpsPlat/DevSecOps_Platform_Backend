package com.backend.devsecopsplatform_backend.controller.appmgmt;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.util.UUID;

/** Variable d'environnement fournie à la création/édition d'un service ou en CRUD dédié. */
@Data
public class EnvVarRequest {

    /** Présent lors d'une mise à jour d'une variable existante. */
    private UUID id;

    @NotBlank(message = "La clé de la variable est obligatoire")
    private String varKey;

    private String varValue;

    @JsonProperty("isSecret")
    private boolean isSecret = false;
}
